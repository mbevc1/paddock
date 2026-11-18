#!/usr/bin/env bash
# T0.8 Shell jail (§7.5) with private procfs, masked user@ and the user slice.
source "$(dirname "$0")/lib.sh"
poc_start
install_unit_templates

vh_create 1 1 8.3
vh_create 2 2 8.3
on_cleanup "remove_owner_slice 1"
on_cleanup "remove_owner_slice 2"
id=$(vh_id 1)
uid=$(vh_uid 1)
install_sshd_dropin
on_cleanup remove_sshd_dropin
jail_create 1 shell
key=$(ssh_key_for 1)

for sub in usr opt/remi; do
	opts=$(findmnt -no OPTIONS "$JAIL/$id/$sub")
	check "$sub mounted ro,nosuid,nodev ($opts)" bash -c "grep -q '\\bro\\b' <<<'$opts' && grep -q nosuid <<<'$opts' && grep -q nodev <<<'$opts'"
done
check "user@$uid.service masked" test "$(systemctl is-enabled "user@$uid.service" 2>&1)" = masked

sh_jail() { ssh_as "$key" "$id" "bash -lc '$1'" 2>&1; }

out=$(sh_jail 'id -un')
check "login works with user@ masked ($out)" test "$out" = "$id"
out=$(sh_jail 'ps -eo uid= | tr -d " " | sort -u | tr "\n" " "')
check "shell sees only its own processes ($out)" test "$out" = "$uid "
out=$(sh_jail 'getent passwd | cut -d: -f1 | tr "\n" " "')
check "shell sees only its own user ($out)" test "$out" = "$id "
out=$(sh_jail 'ls -A / | tr "\n" " "')
info "jail root: $out"
refute "jail root has no srv" grep -qw srv <<<"$out"
out=$(sh_jail 'php -v | head -1')
check "php -v is PHP 8.3 ($out)" grep -q '^PHP 8\.3' <<<"$out"
out=$(sh_jail 'cat /proc/self/cgroup')
check "session lands in user-$uid.slice ($out)" grep -q "user-$uid.slice" <<<"$out"
out=$(sh_jail 'sudo -n id -u')
refute "sudo cannot gain root ($out)" test "$out" = 0
out=$(sh_jail 'su -c "id -u" root </dev/null')
refute "su cannot gain root ($out)" test "$out" = 0
out=$(sh_jail 'grep NoNewPrivs /proc/self/status; ls -l /usr/bin/sudo')
info "privilege state: $(tr '\n' ' ' <<<"$out")"
