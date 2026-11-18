#!/usr/bin/env bash
# T0.12 Red team: every attempt from §7.7, made by vhost A against vhost B, must fail.
# Attempts run from A's PHP (sandbox and SELinux apply) and, where noted, from a plain process
# with A's UID in the host namespaces, so each layer is tested on its own.
source "$(dirname "$0")/lib.sh"
poc_start
install_unit_templates
apply_sysctl
install_nft_rule
on_cleanup remove_nft_rule
install_sshd_dropin
on_cleanup remove_sshd_dropin

FRONT=1 vh_create 1 1 8.3 a.test 20
FRONT=1 vh_create 2 2 8.3 b.test 1024
on_cleanup "remove_owner_slice 1"
on_cleanup "remove_owner_slice 2"
db_create_primary 1 app
db_create_primary 2 app
jail_create 1 shell
key=$(ssh_key_for 1)

A=$(vh_id 1)
B=$(vh_id 2)
TOKEN=redteam-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
install -o "$B" -g "$B" -m 0600 /dev/null "$WWW/$B/private/secret.txt"
echo "$TOKEN" >"$WWW/$B/private/secret.txt"
mysql "${B}_app" -e "CREATE TABLE secret (v VARCHAR(64)); INSERT INTO secret VALUES ('$TOKEN');"
b_pid=$(vh_pid 2)
b_httpd_pid=$(systemctl show -p MainPID --value "$(httpd_unit 2)")

no_token() {
	local desc=$1 out=$2
	if grep -qF "$TOKEN" <<<"$out"; then fail "$desc"; else pass "$desc"; fi
}
front() { curl -sk -m 15 --resolve "$1:443:127.0.0.1" "https://$1$2"; }

# 1. Read B's files.
no_token "A's PHP cannot read B's file" "$(php_probe 1 "cat $WWW/$B/private/secret.txt")"
out=$(php_probe 1 "ls -a $WWW")
check "A's PHP sees only its own tree in $WWW ($(tr '\n' ' ' <<<"$out"))" test "$(grep -vxE '\.|\.\.' <<<"$out")" = "$A"
no_token "A's UID cannot read B's file in the host namespace" "$(as_uid 1 cat "$WWW/$B/private/secret.txt" 2>&1)"
no_token "the front Apache user cannot read B's file" \
	"$(setpriv --reuid=apache --regid=apache --init-groups -- cat "$WWW/$B/private/secret.txt" 2>&1)"

# 2. Make a shared web server read B's files.
ln -s "$WWW/$B/private/secret.txt" "$WWW/$A/public/leak.txt"
chown -h "$A:$A" "$WWW/$A/public/leak.txt"
no_token "symlink in A's tree does not serve B's file" "$(front a.test /leak.txt)"
install -d -o "$A" -g "$A" "$WWW/$A/public/rw"
printf 'RewriteEngine On\nRewriteRule ^x$ %s [L]\n' "$WWW/$B/private/secret.txt" >"$WWW/$A/public/rw/.htaccess"
chown "$A:$A" "$WWW/$A/public/rw/.htaccess"
no_token "rewrite in A's .htaccess does not serve B's file" "$(front a.test /rw/x)"
install -d -o "$A" -g "$A" "$WWW/$A/public/fs"
printf 'Options +FollowSymLinks\n' >"$WWW/$A/public/fs/.htaccess"
ln -s "$WWW/$B/private/secret.txt" "$WWW/$A/public/fs/leak.txt"
chown -h "$A:$A" "$WWW/$A/public/fs/.htaccess" "$WWW/$A/public/fs/leak.txt"
no_token "FollowSymLinks in A's .htaccess does not serve B's file" "$(front a.test /fs/leak.txt)"
no_token "Host header for B on A's backend does not serve B's files" "$(backend_get 1 /private/secret.txt b.test)"

# 3. Run code as B through B's PHP socket.
refute "B's FPM socket path is absent in A's PHP" test -n "$(php_probe 1 "test -e $RUN_FPM/$B/php.sock && echo present")"
r=$(as_uid 1 "$(php_cli 8.3)" -r "\$s = @stream_socket_client('unix://$RUN_FPM/$B/php.sock'); echo \$s ? 'OPEN' : 'DENIED';")
check "A's UID cannot connect to B's FPM socket ($r)" test "$r" = DENIED
check "B's FPM socket is 0600 and owned by B" test "$(stat -c '%a %U' "$RUN_FPM/$B/php.sock")" = "600 $B"

# 4. Connect to B's backend on loopback.
r=$(php_eval 1 "\$f = @fsockopen('$(vh_addr 2)', 81, \$e, \$s, 3); echo \$f ? 'OPEN' : 'BLOCKED';")
check "A's PHP cannot connect to B's backend ($r)" test "$r" = BLOCKED
refute "A's UID cannot connect to B's backend" as_uid 1 curl -sf -m 5 "http://$(vh_addr 2):81/"

# 5. Squat B's backend address while it restarts.
systemctl stop "$(httpd_unit 2)"
r=$(as_uid 1 "$(php_cli 8.3)" -r "\$s = @stream_socket_server('tcp://$(vh_addr 2):81', \$e, \$m); echo \$s ? 'BOUND' : 'DENIED';")
check "A's UID cannot bind B's backend address ($r)" test "$r" = DENIED
r=$(php_eval 1 "\$s = @stream_socket_server('tcp://$(vh_addr 2):81', \$e, \$m); echo \$s ? 'BOUND' : 'DENIED';")
check "A's PHP cannot bind B's backend address ($r)" test "$r" = DENIED
check "unprivileged port start is 1024" test "$(sysctl -n net.ipv4.ip_unprivileged_port_start)" = 1024
systemctl start "$(httpd_unit 2)"
b_httpd_pid=$(systemctl show -p MainPID --value "$(httpd_unit 2)")

# 6. List or inspect B's processes.
out=$(php_probe 1 'ps -eo uid= | tr -d " " | sort -u | tr "\n" " "')
check "A's PHP sees only A's processes ($out)" test "$out" = "$(vh_uid 1) "
refute "A's PHP cannot see B's FPM in /proc" test -n "$(php_probe 1 "test -d /proc/$b_pid && echo visible")"
refute "A's PHP cannot signal B's FPM" test -n "$(php_probe 1 "kill -0 $b_pid && echo signalled")"
refute "A's UID cannot signal B's backend" as_uid 1 kill -0 "$b_httpd_pid"
refute "A's UID cannot read B's environment" as_uid 1 cat "/proc/$b_pid/environ"

# 7. Read B's temp files, shared memory, IPC.
key_hex=$(php_probe 2 "echo b >/tmp/b-$TOKEN; echo b >/dev/shm/b-$TOKEN; ipcmk -M 4096 | awk '{print \$NF}'")
info "B created SysV segment: $key_hex"
no_token "A's PHP cannot see B's /tmp or /dev/shm files" "$(php_probe 1 'ls -a /tmp /dev/shm')"
# shellcheck disable=SC2016 # expanded by the probe's shell
b_ids=$(php_probe 2 'ipcs -m | awk "NR>3 {print \$2}" | tr "\n" " "')
# shellcheck disable=SC2016
a_ids=$(php_probe 1 'ipcs -m | awk "NR>3 {print \$2}" | tr "\n" " "')
check "A's PHP does not see B's shared memory (A: '$a_ids', B: '$b_ids')" test -z "${a_ids// /}"

# 8. Read B's databases.
mysqli() {
	php_eval 1 "mysqli_report(MYSQLI_REPORT_OFF);
\$m = @new mysqli('localhost', '$1', '', '$2');
if (\$m->connect_errno) { echo 'ERR'; exit; }
\$r = @\$m->query('$3');
echo \$r ? implode(',', array_column(\$r->fetch_all(), 0)) : 'ERR';"
}
no_token "A's PHP cannot log in as B's DB user" "$(mysqli "$B" "${B}_app" 'SELECT v FROM secret')"
no_token "A's DB user cannot read B's database" "$(mysqli "$A" "${A}_app" "SELECT v FROM ${B}_app.secret")"
no_token "A's PHP cannot log in as root" "$(mysqli root '' "SELECT v FROM ${B}_app.secret")"

# 9. See B through SFTP or a shell.
sh_jail() { ssh_as "$key" "$A" "bash -lc '$1'" 2>&1; }
out=$(sh_jail 'ls -A / | tr "\n" " "')
refute "A's shell has no /srv ($out)" grep -qw srv <<<"$out"
check "A's shell lists only its own user" test "$(sh_jail 'getent passwd | cut -d: -f1')" = "$A"
out=$(sh_jail 'ps -eo uid= | tr -d " " | sort -u | tr "\n" " "')
check "A's shell sees only A's processes ($out)" test "$out" = "$(vh_uid 1) "
no_token "A's shell cannot read B's file" "$(sh_jail "cat $WWW/$B/private/secret.txt /site/../../$B/private/secret.txt")"

# 10. Starve B of CPU, memory, disk.
for prop in MemoryMax CPUQuotaPerSecUSec TasksMax; do
	v=$(systemctl show -p "$prop" --value "$(owner_slice 1)")
	check "$(owner_slice 1) has $prop set ($v)" test -n "$v" -a "$v" != infinity
done
out=$(php_probe 1 "dd if=/dev/zero of=$WWW/$A/tmp/fill bs=1M count=40")
check "A's disk writes stop at its 20 MB project quota" grep -qi 'quota exceeded' <<<"$out"
out=$(php_probe 2 "dd if=/dev/zero of=$WWW/$B/tmp/fill bs=1M count=5 && echo written")
check "B can still write after A filled its quota" grep -q written <<<"$out"

# 11. Gain privileges.
check "A's PHP runs with NoNewPrivs" grep -qE 'NoNewPrivs:[[:space:]]+1' <<<"$(php_probe 1 'cat /proc/self/status')"
refute "sudo in A's PHP cannot reach root" test "$(php_probe 1 'sudo -n id -u')" = 0
refute "su in A's shell cannot reach root" test "$(sh_jail 'su -c "id -u" root </dev/null')" = 0
check "user namespaces are disabled" test "$(sysctl -n user.max_user_namespaces)" = 0
refute "A's PHP cannot create a user namespace" test -n "$(php_probe 1 'unshare -U true && echo created')"

# Subordinate ID ranges that cover vhost UIDs would let their holder map into a tenant.
overlaps=$(awk -F: '$2 <= 165535 && $2 + $3 > 100000 {print $1 ":" $2 ":" $3}' /etc/subuid /etc/subgid | sort -u | tr '\n' ' ')
check "no subordinate ID range covers vhost UIDs 100001-165535 (${overlaps:-none})" test -z "$overlaps"
