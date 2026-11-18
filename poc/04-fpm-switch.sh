#!/usr/bin/env bash
# T0.4 Remi FPM SELinux label and the §8 PHP switch under a 1 req/s loop.
source "$(dirname "$0")/lib.sh"
poc_start
install_unit_templates

for v in "${PHP_VERSIONS[@]}"; do
	bin=/opt/remi/php$(php_tag "$v")/root/usr/sbin/php-fpm
	info "label of $bin: $(stat -c %C "$bin")"
done

vh_create 1 1 8.3
on_cleanup "remove_owner_slice 1"
id=$(vh_id 1)
echo '<?php echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION;' >"$WWW/$id/public/v.php"
chown "$id:$id" "$WWW/$id/public/v.php"

# php-fpm -t refuses to run as root without a pool user, so test as the vhost user.
check "FPM config passes php-fpm -t for 8.4" setpriv --reuid="$id" --regid="$id" --clear-groups -- \
	/opt/remi/php84/root/usr/sbin/php-fpm -t --fpm-config "$ETC_PADDOCK/fpm/$id.conf"

pid=$(vh_pid 1)
ctx=$(ps -o label= -p "$pid")
check "FPM 8.3 runs in httpd_t ($ctx)" grep -q ':httpd_t:' <<<"$ctx"

log=$POC_TMP/loop.log
(
	while :; do
		setpriv --reuid=apache --regid=apache --init-groups -- \
			curl -s -m 5 -o - -w ' %{http_code}\n' -H "Host: $id.test" "http://$(vh_addr 1):81/v.php" >>"$log" || echo "curl-error" >>"$log"
		sleep 1
	done
) &
loop=$!
on_cleanup "kill $loop"
sleep 5
start=$(date +%s%N)
vh_php_switch 1 8.4
info "switch took $((($(date +%s%N) - start) / 1000000)) ms"
sleep 5
kill "$loop"
wait "$loop" 2>/dev/null || true

info "loop results: $(sort "$log" | uniq -c | tr '\n' ';')"
check "no failed requests during the switch" bash -c "! grep -qv ' 200\$' '$log'"
check "requests served by 8.3 before the switch" grep -q '^8.3 200$' "$log"
check "requests served by 8.4 after the switch" test "$(tail -1 "$log")" = "8.4 200"
check "socket still present after the old FPM stopped" test -S "$RUN_FPM/$id/php.sock"
refute "old unit $(fpm_unit 1 8.3) inactive" systemctl is-active "$(fpm_unit 1 8.3)"
ctx=$(ps -o label= -p "$(vh_pid 1)")
check "FPM 8.4 runs in httpd_t ($ctx)" grep -q ':httpd_t:' <<<"$ctx"
