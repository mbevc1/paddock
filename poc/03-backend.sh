#!/usr/bin/env bash
# T0.3 Backend Apache as the vhost user (§7.1, §7.2).
source "$(dirname "$0")/lib.sh"
poc_start
install_unit_templates

for m in mpm_event unixd systemd authz_core authz_host authn_core authn_file auth_basic authz_user \
	access_compat alias dir mime log_config setenvif env headers expires deflate filter rewrite \
	remoteip proxy proxy_fcgi; do
	check "module file mod_$m.so exists" test -f "/etc/httpd/modules/mod_$m.so"
done

vh_create 1 1 8.3
on_cleanup "remove_owner_slice 1"
id=$(vh_id 1)

check "backend config passes httpd -t" httpd -t -f "$ETC_PADDOCK/httpd/$id.conf"
check "$(httpd_unit 1) active" systemctl is-active "$(httpd_unit 1)"
pid=$(systemctl show -p MainPID --value "$(httpd_unit 1)")
check "backend runs as $id" test "$(ps -o user= -p "$pid")" = "$id"
ctx=$(ps -o label= -p "$pid")
check "backend runs in httpd_t ($ctx)" grep -q ':httpd_t:' <<<"$ctx"
check "backend listens on $(vh_addr 1):81" bash -c "ss -ltnH | grep -qF '$(vh_addr 1):81'"

echo static-ok >"$WWW/$id/public/hello.txt"
echo '<?php echo "php-", PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION;' >"$WWW/$id/public/v.php"
chown "$id:$id" "$WWW/$id/public/hello.txt" "$WWW/$id/public/v.php"
check "backend serves a static file" test "$(backend_get 1 /hello.txt)" = static-ok
check "backend serves PHP 8.3 through FPM" test "$(backend_get 1 /v.php)" = php-8.3
check "access log written as $id" test "$(stat -c %U "$WWW/$id/logs/access.log")" = "$id"
