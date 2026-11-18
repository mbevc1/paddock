#!/usr/bin/env bash
# T0.5 MariaDB from the sandbox (§9).
source "$(dirname "$0")/lib.sh"
poc_start
install_unit_templates

vh_create 1 1 8.3
vh_create 2 2 8.3
on_cleanup "remove_owner_slice 1"
on_cleanup "remove_owner_slice 2"
db_create_primary 1 wp
db_create_primary 2 wp
# Matches v00001_wp if the grant's "_" were left unescaped.
mysql -e "CREATE DATABASE IF NOT EXISTS \`v00001xwp\`"
on_cleanup "mysql -e 'DROP DATABASE IF EXISTS \`v00001xwp\`'"

connect() {
	local user=$1 db=$2
	php_eval 1 "mysqli_report(MYSQLI_REPORT_OFF);
\$m = @new mysqli('localhost', '$user', '', '$db');
echo \$m->connect_errno ? 'ERR ' . \$m->connect_error : 'OK';"
}

info "grants: $(mysql -N -e "SHOW GRANTS FOR 'v00001'@'localhost'" | tr '\n' ';')"
check "A connects passwordless via unix_socket to v00001_wp" test "$(connect v00001 v00001_wp)" = OK
r=$(connect v00002 v00002_wp)
check "A cannot connect as B's user ($r)" grep -q '^ERR' <<<"$r"
r=$(connect v00001 v00001xwp)
check "escaped grant denies v00001xwp ($r)" grep -q '^ERR' <<<"$r"
r=$(connect v00001 v00002_wp)
check "A cannot open B's database ($r)" grep -q '^ERR' <<<"$r"
r=$(connect root '')
check "A cannot connect as root ($r)" grep -q '^ERR' <<<"$r"
listeners=$(ss -ltnH 'sport = :3306' | awk '{print $4}' | sort -u | tr '\n' ' ')
check "MariaDB listens only on 127.0.0.1:3306 ($listeners)" test "$listeners" = "127.0.0.1:3306 "
