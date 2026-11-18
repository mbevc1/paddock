#!/usr/bin/env bash
# T0.2 Sandbox visibility: two vhosts with the §7.1 drop-in, checked from inside A's FPM unit.
source "$(dirname "$0")/lib.sh"
poc_start
install_unit_templates

vh_create 1 1 8.3 "" 1024 fpm
vh_create 2 2 8.3 "" 1024 fpm
on_cleanup "remove_owner_slice 1"
on_cleanup "remove_owner_slice 2"

check "A sees only its own tree in /srv/www" test "$(vh_run 1 ls -A /srv/www)" = v00001
check "A sees an empty /srv/jail" test -z "$(vh_run 1 ls -A /srv/jail)"
refute "A cannot see B's FPM socket path" vh_run 1 test -e "$RUN_FPM/v00002/php.sock"
check "A's /run/paddock holds only its own FPM directory" test \
	"$(vh_run 1 find /run/paddock -mindepth 1 -maxdepth 2 | sort | tr '\n' ' ')" = \
	"/run/paddock/fpm /run/paddock/fpm/v00001 "
refute "A cannot list /home" vh_run 1 ls /home

vh_run 2 sh -c 'echo b >/dev/shm/pdpoc-b && echo b >/tmp/pdpoc-b'
check "B wrote its /dev/shm marker" vh_run 2 test -e /dev/shm/pdpoc-b
refute "A's /dev/shm is private" vh_run 1 test -e /dev/shm/pdpoc-b
refute "host /dev/shm does not see B's marker" test -e /dev/shm/pdpoc-b
refute "A's /tmp is private" vh_run 1 test -e /tmp/pdpoc-b

uids=$(vh_run 1 ps -eo uid= | tr -d ' ' | sort -u | tr '\n' ' ')
check "ps in A shows only A's processes (uids: $uids)" test "$uids" = "$(vh_uid 1) "

pid=$(vh_pid 1)
check "A's FPM has NoNewPrivs" grep -qE '^NoNewPrivs:[[:space:]]+1' "/proc/$pid/status"
check "A's FPM runs in $(owner_slice 1)" test \
	"$(systemctl show -p Slice --value "$(fpm_unit 1 8.3)")" = "$(owner_slice 1)"
check "A's FPM runs as $(vh_id 1)" test "$(ps -o user= -p "$pid")" = "$(vh_id 1)"
