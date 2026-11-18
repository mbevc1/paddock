#!/usr/bin/env bash
# T0.10 WordPress in vhost A behind the front proxy, updated through PHP-FPM with FS_METHOD=direct.
source "$(dirname "$0")/lib.sh"
poc_start
install_unit_templates

readonly DOMAIN=shop.test
readonly OLD_CORE=${POC_WP_OLD_CORE:-6.5.5}
readonly OLD_PLUGIN=classic-editor
readonly OLD_PLUGIN_VERSION=${POC_WP_OLD_PLUGIN:-1.6.3}

FRONT=1 vh_create 1 1 8.3 "$DOMAIN"
on_cleanup "remove_owner_slice 1"
db_create_primary 1 wp
id=$(vh_id 1)
pub=$WWW/$id/public

wp_as() { vh_run 1 "$(php_cli 8.3)" /usr/local/bin/wp --path="$pub" "$@"; }
front() { curl -sk -m "${2:-30}" --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN$1"; }
front_status() { curl -sk -m 30 -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN$1"; }

check "wp core download $OLD_CORE" wp_as core download --version="$OLD_CORE" --locale=en_US
check "wp config create" wp_as config create --dbname="${id}_wp" --dbuser="$id" \
	--dbhost="localhost:$MYSQL_SOCK" --skip-check
check "FS_METHOD=direct set" wp_as config set FS_METHOD direct
check "wp core install" wp_as core install --url="https://$DOMAIN" --title=Paddock-PoC \
	--admin_user=poc-admin --admin_password="$(head -c 18 /dev/urandom | base64)" \
	--admin_email="admin@$DOMAIN" --skip-email
check "install old $OLD_PLUGIN $OLD_PLUGIN_VERSION" wp_as plugin install "$OLD_PLUGIN" --version="$OLD_PLUGIN_VERSION"

cat >"$pub/poc-upgrade.php" <<'PHP'
<?php
define('WP_ADMIN', true);
require __DIR__ . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/admin.php';
require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
wp_set_current_user(1);
$skin = new Automatic_Upgrader_Skin();
$result = null;
switch ($_GET['a'] ?? '') {
case 'method':
    echo get_filesystem_method();
    exit;
case 'core':
    wp_version_check([], true);
    $offer = get_preferred_from_update_core();
    if (!$offer || $offer->response !== 'upgrade') {
        echo 'NO-OFFER';
        exit;
    }
    $result = (new Core_Upgrader($skin))->upgrade($offer);
    break;
case 'plugin-install':
    $api = plugins_api('plugin_information', ['slug' => 'health-check', 'fields' => ['sections' => false]]);
    $result = is_wp_error($api) ? $api : (new Plugin_Upgrader($skin))->install($api->download_link);
    break;
case 'plugin-update':
    wp_update_plugins();
    $result = (new Plugin_Upgrader($skin))->upgrade('classic-editor/classic-editor.php');
    break;
}
if (is_wp_error($result)) {
    echo 'ERR ', $result->get_error_message();
} elseif ($result) {
    echo 'OK';
} else {
    echo 'FAIL ', implode(' | ', $skin->get_upgrade_messages());
}
PHP
chown "$id:$id" "$pub/poc-upgrade.php"

check "filesystem method is direct" test "$(front '/poc-upgrade.php?a=method')" = direct
r=$(front '/poc-upgrade.php?a=core' 600)
check "core update through FPM ($r)" test "$r" = OK
r=$(front '/poc-upgrade.php?a=plugin-install' 600)
check "plugin install through FPM ($r)" test "$r" = OK
r=$(front '/poc-upgrade.php?a=plugin-update' 600)
check "plugin update through FPM ($r)" test "$r" = OK
info "core now $(wp_as core version), $OLD_PLUGIN now $(wp_as plugin get "$OLD_PLUGIN" --field=version)"
check "files written by updates belong to $id" test -z "$(find "$pub" ! -user "$id" -print -quit)"

install -d -o "$id" -g "$id" "$pub/wp-content/uploads"
echo '<?php echo "executed";' >"$pub/wp-content/uploads/evil.php"
chown "$id:$id" "$pub/wp-content/uploads/evil.php"
check "uploads refuse PHP execution" test "$(front_status /wp-content/uploads/evil.php)" = 403
echo '<?php require __DIR__ . "/wp-load.php"; echo is_ssl() ? "https" : "http";' >"$pub/poc-ssl.php"
chown "$id:$id" "$pub/poc-ssl.php"
check "WordPress detects HTTPS behind the front proxy" test "$(front /poc-ssl.php)" = https
check "home page answers 200 over HTTPS" test "$(front_status /)" = 200
