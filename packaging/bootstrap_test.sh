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

rpm() { return 1; }
(install_remi >/dev/null 2>&1) && fail "install_remi ran with no pinned fingerprint"
unset -f rpm

if [[ $failures -gt 0 ]]; then
	echo "bootstrap_test: $failures failures"
	exit 1
fi
echo "bootstrap_test: ok"
