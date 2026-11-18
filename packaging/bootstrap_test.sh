#!/usr/bin/env bash
# Tests bootstrap.sh's host-independent functions. Sourcing defines functions only; main never runs.
set -uo pipefail
cd "$(dirname "$0")"
# shellcheck source=packaging/bootstrap.sh
source ./bootstrap.sh
set +e

failures=0
fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}
expect() { "$@" || fail "expected success: $*"; }
reject() { ! "$@" || fail "expected failure: $*"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

for h in panel.example.com a.b xn--bcher-kva.example 1panel.example.com; do expect valid_hostname "$h"; done
for h in "" localhost Panel.Example.com "panel.example.com." "a..b" "-a.example.com" "a_b.example.com" \
	"panel.example.com;id" $'panel.example.com\nx' 10.0.0.1 "a.$(printf 'b%.0s' {1..64}).com"; do
	reject valid_hostname "$h"
done
expect valid_email ops@example.com
for e in "ops" "ops@localhost" "o ps@example.com" $'ops@example.com\nMDCAChallenges x' "a@b@example.com"; do
	reject valid_email "$e"
done
expect valid_admin admin
for a in "" Admin "1admin" "ad min" "admin;rm"; do reject valid_admin "$a"; done
expect valid_device /dev/vdb
expect valid_device /dev/disk/by-id/virtio-www
for d in vdb /dev/../etc/passwd "/dev/vdb x" /tmp/x; do reject valid_device "$d"; done
for size in 20G 1T 999999G; do expect valid_size "$size"; done
for size in "" 0G 20 20M 20g 1.5G -5G "20G;id" 1000000G; do reject valid_size "$size"; done

printf 'UUID=1 / xfs defaults 0 0\n' >"$WORK/fstab"
reject fstab_has_www "$WORK/fstab"
printf '# /dev/vdb /srv/www xfs prjquota 0 0\n' >>"$WORK/fstab"
reject fstab_has_www "$WORK/fstab"
printf '/var/lib/paddock/www.img /srv/www xfs loop,prjquota 0 0\n' >>"$WORK/fstab"
expect fstab_has_www "$WORK/fstab"
printf 'UUID=2 /srv/www-old xfs defaults 0 0\n' >"$WORK/fstab2"
reject fstab_has_www "$WORK/fstab2"

: >"$WORK/local.rpm"
args_fail() { (parse_args --hostname panel.example.com --rpm "$WORK/local.rpm" "$@") >/dev/null 2>&1 && fail "parse_args accepted: $*"; }
args_ok() { (parse_args --hostname panel.example.com --rpm "$WORK/local.rpm" "$@") >/dev/null 2>&1 || fail "parse_args refused: $*"; }
args_ok --www-file 20G
args_ok --www-device /dev/vdb --format
args_fail --www-device /dev/vdb --www-file 20G
args_fail --www-file 20G --format
args_fail --www-file 20MB

expect version_at_least 9.4 9.4
expect version_at_least 9.10 9.4
reject version_at_least 9.3 9.4

ss() { printf '%s\n' 'LISTEN 0 511 *:443 *:* users:(("httpd",pid=1,fd=4),("nginx",pid=2,fd=4))'; }
[[ $(port_users 443 | tr '\n' ' ') == "httpd nginx " ]] || fail "port_users = $(port_users 443)"
unset -f ss

dst=$WORK/etc/x/panel.conf
printf 'ServerName @HOSTNAME@\n' >"$WORK/src"
install_file "$WORK/src" "$dst" panel.example.com >/dev/null
[[ $(cat "$dst") == "ServerName panel.example.com" ]] || fail "install_file content: $(cat "$dst")"
[[ ${#CHANGED[@]} -eq 1 ]] || fail "first install not recorded: ${CHANGED[*]}"
install_file "$WORK/src" "$dst" panel.example.com >/dev/null
[[ ${#CHANGED[@]} -eq 1 ]] || fail "unchanged file rewritten"
changed "$WORK/etc/x/" || fail "changed misses the directory"
reject changed "$WORK/etc/y/"
printf '%s\nlocal edit\n' "$KEEP" >"$dst"
install_file "$WORK/src" "$dst" panel.example.com >/dev/null
grep -q 'local edit' "$dst" || fail "keep marker ignored"
[[ -z $(find "$WORK/etc/x" -name 'panel.conf.*') ]] || fail "temporary files left behind"

export GNUPGHOME=$WORK/gnupg
mkdir -m 0700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-gen-key 'Test Key <test@example.com>' ed25519 sign never 2>/dev/null
gpg --batch --armor --export test@example.com >"$WORK/key.asc"
fpr=$(gpg --batch --with-colons --list-keys test@example.com 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')
expect key_pinned "$WORK/key.asc" 0000000000000000000000000000000000000000 "$fpr"
if [[ ${fpr: -1} == 0 ]]; then other=${fpr%?}1; else other=${fpr%?}0; fi
reject key_pinned "$WORK/key.asc" "$other"
reject key_pinned "$WORK/key.asc"
printf 'not a key\n' >"$WORK/junk"
reject key_pinned "$WORK/junk" "$fpr"

cat >"$WORK/subuid" <<'EOF'
mare:100000:65536
ispconfig:231072:65536
below:999934465:65536
covering:999934465:65537
inside:1000000100:10
above:1000065536:65536
EOF
[[ $(subid_overlaps "$WORK/subuid" | tr '\n' ' ') == "covering:999934465:65537 inside:1000000100:10 " ]] ||
	fail "subid_overlaps = $(subid_overlaps "$WORK/subuid")"
[[ -z $(subid_overlaps "$WORK/missing") ]] || fail "subid_overlaps on a missing file"

printf 'SUB_UID_MIN\t\t   100000\nSUB_UID_MAX\t\t600100000\n# SUB_GID_MAX 2000000000\n' >"$WORK/login.defs"
[[ $(login_def "$WORK/login.defs" SUB_UID_MAX) == 600100000 ]] || fail "login_def SUB_UID_MAX"
[[ -z $(login_def "$WORK/login.defs" SUB_GID_MAX) ]] || fail "login_def read a commented-out key"

if grep -E '^[[:space:]]*firewall-cmd .*--add-service.*--add-port|^[[:space:]]*firewall-cmd .*--add-port.*--add-service' ./bootstrap.sh; then
	fail "a firewall-cmd call mixes --add-service and --add-port, which firewall-cmd refuses"
fi

apachectl() {
	echo "AH00526: Syntax error on line 16 of /etc/httpd/conf.d/old.conf"
	return 1
}
out=$( (check_apache) 2>&1) && fail "check_apache passed a failing configtest"
[[ $out == *AH00526*old.conf* ]] || fail "check_apache does not show Apache's error: $out"
apachectl() { echo "Syntax OK"; }
(check_apache) >/dev/null 2>&1 || fail "check_apache failed a passing configtest"
unset -f apachectl
(PATH=/nonexistent check_apache) >/dev/null 2>&1 || fail "check_apache failed without Apache installed"

[[ ${#REMI_FINGERPRINTS[@]} -gt 0 ]] || fail "no Remi fingerprint pinned"
for f in "${REMI_FINGERPRINTS[@]}"; do
	[[ $f =~ ^[0-9A-F]{40}$ ]] || fail "Remi fingerprint $f is not 40 uppercase hex digits"
done

if [[ $failures -gt 0 ]]; then
	echo "bootstrap_test: $failures failures"
	exit 1
fi
echo "bootstrap_test: ok"
