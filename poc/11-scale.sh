#!/usr/bin/env bash
# T0.11 Scale: idle vhosts, memory per vhost, start time, daemon-reload time, boot time.
# Usage:
#   11-scale.sh create [COUNT]   create and start COUNT vhosts (default 500), keep them
#   11-scale.sh report           after a reboot: time from boot until every vhost unit was active
#   11-scale.sh cleanup          remove every vhost the create step made
# Vhosts are grouped five per owner, the default max_vhosts, so each owner slice keeps its default limits.
source "$(dirname "$0")/lib.sh"

readonly STATE=/var/lib/paddock-poc/scale.count
readonly PER_OWNER=5
owner_of() { echo $(((($1 - 1) / PER_OWNER) + 1)); }

units() {
	local count=$1 n
	for ((n = 1; n <= count; n++)); do
		echo "$(fpm_unit "$n" 8.3)" "$(httpd_unit "$n")"
	done
}

mem_available_mb() { awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo; }

create() {
	local count=${1:-500} n before after t0 t1
	install_unit_templates
	before=$(mem_available_mb)
	t0=$(date +%s)
	for ((n = 1; n <= count; n++)); do
		vh_create "$n" "$(owner_of "$n")" 8.3 "" 1024 no
		echo '<?php echo "ok";' >"$WWW/$(vh_id "$n")/public/i.php"
		chown "$(vh_id "$n"):$(vh_id "$n")" "$WWW/$(vh_id "$n")/public/i.php"
		((n % 50 == 0)) && info "created $n"
	done
	echo "$count" >"$STATE"
	info "created $count vhosts in $(($(date +%s) - t0)) s"

	local reload_ms
	t0=$(date +%s%N)
	systemctl daemon-reload
	reload_ms=$((($(date +%s%N) - t0) / 1000000))
	info "systemctl daemon-reload: $reload_ms ms"

	t0=$(date +%s%N)
	# shellcheck disable=SC2046 # one unit name per word
	systemctl enable --now $(units "$count" | tr ' ' '\n' | grep fpm)
	# shellcheck disable=SC2046
	systemctl enable --now $(units "$count" | tr ' ' '\n' | grep httpd)
	t1=$(date +%s%N)
	info "started $((count * 2)) units in $(((t1 - t0) / 1000000)) ms"

	local failed=0
	for ((n = 1; n <= count; n++)); do
		systemctl -q is-active "$(fpm_unit "$n" 8.3)" "$(httpd_unit "$n")" || failed=$((failed + 1))
	done
	check "all $count vhosts active ($failed failed)" test "$failed" = 0
	check "a sample vhost answers" test "$(backend_get "$count" /i.php)" = ok

	sleep 30
	after=$(mem_available_mb)
	info "MemAvailable before ${before} MB, after ${after} MB"
	info "memory per idle vhost: $(((before - after) * 1024 / count)) KiB"
	info "paddock.slice MemoryCurrent: $(systemctl show -p MemoryCurrent --value paddock.slice)"

	t0=$(date +%s%N)
	systemctl daemon-reload
	info "systemctl daemon-reload with $count vhosts: $((($(date +%s%N) - t0) / 1000000)) ms"
	info "now reboot and run: $0 report"
	# Keep the vhosts: the report step needs them after a reboot.
	CREATED_VHOSTS=()
}

report() {
	local count latest=0 n ts unit
	count=$(cat "$STATE")
	for ((n = 1; n <= count; n++)); do
		for unit in "$(fpm_unit "$n" 8.3)" "$(httpd_unit "$n")"; do
			ts=$(systemctl show -p ActiveEnterTimestampMonotonic --value "$unit")
			[[ $ts -gt $latest ]] && latest=$ts
		done
	done
	info "$(systemd-analyze | head -1)"
	info "all $count vhosts active $((latest / 1000000)).$(((latest / 1000) % 1000)) s after boot"
	local failed=0
	for ((n = 1; n <= count; n++)); do
		systemctl -q is-active "$(fpm_unit "$n" 8.3)" "$(httpd_unit "$n")" || failed=$((failed + 1))
	done
	check "all $count vhosts active after reboot ($failed failed)" test "$failed" = 0
	info "MemAvailable: $(mem_available_mb) MB"
}

cleanup() {
	local count n
	count=$(cat "$STATE" 2>/dev/null || echo 0)
	for ((n = 1; n <= count; n++)); do CREATED_VHOSTS+=("$n"); done
	for ((n = 1; n <= count; n += PER_OWNER)); do on_cleanup "remove_owner_slice $(owner_of "$n")"; done
	on_cleanup "rm -f '$STATE'"
}

poc_start
case ${1:-} in
create) create "${2:-500}" ;;
report) report ;;
cleanup) cleanup ;;
*) echo "usage: $0 create [COUNT] | report | cleanup" >&2 && exit 2 ;;
esac
