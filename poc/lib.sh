# shellcheck shell=bash
# Shared helpers for the phase 0 scripts. Source it; do not execute it.
# Renders the files from docs/plan.md §7 so each check exercises the specified design.

set -euo pipefail

POC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export POC_DIR

readonly WWW=/srv/www
readonly JAIL=/srv/jail
readonly RUN_FPM=/run/paddock/fpm
readonly ETC_PADDOCK=/etc/paddock
readonly UNIT_DIR=/etc/systemd/system
readonly MYSQL_SOCK=/var/lib/mysql/mysql.sock
readonly TMPFILES=/etc/tmpfiles.d/paddock-poc.conf
readonly POC_CERT=/etc/pki/tls/certs/localhost.crt
readonly POC_KEY=/etc/pki/tls/private/localhost.key
readonly PHP_VERSIONS=(8.3 8.4)

FAILURES=0
CREATED_VHOSTS=()
CLEANUP_HOOKS=()

pass() { printf 'PASS %s\n' "$*"; }
fail() {
	printf 'FAIL %s\n' "$*"
	FAILURES=$((FAILURES + 1))
}
info() { printf '.... %s\n' "$*"; }

# check DESCRIPTION COMMAND...: PASS when the command succeeds.
check() {
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

# refute DESCRIPTION COMMAND...: PASS when the command fails.
refute() {
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi
}

need_root() {
	if [[ $EUID -ne 0 ]]; then
		echo "FAIL must run as root" >&2
		exit 1
	fi
}

on_cleanup() { CLEANUP_HOOKS+=("$1"); }

run_cleanup() {
	local i
	for ((i = ${#CREATED_VHOSTS[@]} - 1; i >= 0; i--)); do
		vh_destroy "${CREATED_VHOSTS[i]}" || true
	done
	for ((i = ${#CLEANUP_HOOKS[@]} - 1; i >= 0; i--)); do
		eval "${CLEANUP_HOOKS[i]}" || true
	done
	systemctl daemon-reload || true
}

# Call once per script after need_root. Prints the overall result on exit.
poc_start() {
	need_root
	trap 'rc=$?; run_cleanup; report_avc; finish $rc' EXIT
	POC_TMP=$(mktemp -d)
	on_cleanup "rm -rf '$POC_TMP'"
	POC_TS=("$(date '+%x')" "$(date '+%T')")
}

report_avc() {
	if [[ $FAILURES -gt 0 ]] && command -v ausearch >/dev/null; then
		info "SELinux denials since ${POC_TS[*]}:"
		ausearch -m avc -ts "${POC_TS[@]}" 2>/dev/null | grep -E '^type=AVC' | sed 's/^/     /' || true
	fi
}

finish() {
	local rc=$1
	if [[ $rc -ne 0 && $FAILURES -eq 0 ]]; then
		fail "script aborted with exit code $rc"
	fi
	if [[ $FAILURES -eq 0 ]]; then
		echo "RESULT PASS $(basename "$0")"
		exit 0
	fi
	echo "RESULT FAIL $(basename "$0") ($FAILURES failed)"
	exit 1
}

# Identifiers from §5.
vh_id() { printf 'v%05d' "$1"; }
vh_uid() { echo $((100000 + $1)); }
vh_addr() { echo "127.64.$(($1 >> 8)).$(($1 & 255))"; }
php_tag() { echo "${1/./}"; }
fpm_unit() { echo "paddock-php$(php_tag "$2")-fpm@$(vh_id "$1").service"; }
httpd_unit() { echo "paddock-httpd@$(vh_id "$1").service"; }
owner_slice() { echo "paddock-owner-$1.slice"; }

# Runs a command as the vhost user inside the mount and IPC namespaces of its FPM master.
vh_run() {
	local n=$1
	shift
	local pid uid
	pid=$(vh_pid "$n")
	uid=$(vh_uid "$n")
	if [[ -z $pid || $pid == 0 ]]; then
		echo "no FPM main PID for $(vh_id "$n")" >&2
		return 1
	fi
	nsenter --target "$pid" --mount --ipc --setuid "$uid" --setgid "$uid" -- \
		env -i HOME="$WWW/$(vh_id "$n")" PATH=/usr/local/bin:/usr/bin:/bin "$@"
}

vh_pid() { systemctl show -p MainPID --value "$(fpm_unit "$1" "$(vh_php "$1")")"; }
vh_php() { cat "$ETC_PADDOCK/poc/$(vh_id "$1").php"; }
vh_owner() { cat "$ETC_PADDOCK/poc/$(vh_id "$1").owner"; }

# HTTP request to a backend as the apache user, the only UID the loopback rule allows.
backend_get() {
	local n=$1 path=$2 host=${3:-$(vh_id "$1").test}
	setpriv --reuid=apache --regid=apache --init-groups -- \
		curl -sS -m 30 -H "Host: $host" "http://$(vh_addr "$n"):81$path"
}

# Runs shell code as PHP's child inside vhost N's backend: the closest model of tenant code.
# Prints the combined output.
php_probe() {
	local n=$1 code=$2 id name
	id=$(vh_id "$n")
	name="probe-$RANDOM$RANDOM.php"
	printf '<?php passthru(base64_decode("%s"));\n' "$(printf '{ %s\n} 2>&1' "$code" | base64 -w0)" \
		>"$WWW/$id/public/$name"
	chown "$id:$id" "$WWW/$id/public/$name"
	backend_get "$n" "/$name" || true
	rm -f "$WWW/$id/public/$name"
}

# Writes a PHP file into vhost N's public tree and returns its body through the backend.
php_eval() {
	local n=$1 code=$2 id name
	id=$(vh_id "$n")
	name="eval-$RANDOM$RANDOM.php"
	printf '<?php\n%s\n' "$code" >"$WWW/$id/public/$name"
	chown "$id:$id" "$WWW/$id/public/$name"
	backend_get "$n" "/$name" || true
	rm -f "$WWW/$id/public/$name"
}

wait_for() {
	local tries=$1
	shift
	while ((tries-- > 0)); do
		if "$@" >/dev/null 2>&1; then return 0; fi
		sleep 0.5
	done
	return 1
}

# §7.1 unit templates. The backend template ships in the RPM later; the PoC writes it to /etc.
install_unit_templates() {
	cat >"$UNIT_DIR/paddock-httpd@.service" <<'EOF'
[Unit]
Description=Paddock backend Apache for %i
After=network.target

[Service]
Type=notify
User=%i
Group=%i
ExecStart=/usr/sbin/httpd -DFOREGROUND -f /etc/paddock/httpd/%i.conf
ExecReload=/usr/sbin/httpd -f /etc/paddock/httpd/%i.conf -k graceful
RuntimeDirectory=paddock-httpd/%i
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
	local v tag
	for v in "${PHP_VERSIONS[@]}"; do
		tag=$(php_tag "$v")
		cat >"$UNIT_DIR/paddock-php${tag}-fpm@.service" <<EOF
[Unit]
Description=Paddock PHP $v FPM for %i

[Service]
Type=notify
User=%i
Group=%i
ExecStart=/opt/remi/php${tag}/root/usr/sbin/php-fpm --nodaemonize --fpm-config /etc/paddock/fpm/%i.conf
ExecReload=/bin/kill -USR2 \$MAINPID
CapabilityBoundingSet=
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
	done
	systemctl daemon-reload
}

render_sandbox_dropin() {
	local n=$1 owner=$2 id
	id=$(vh_id "$n")
	cat <<EOF
[Service]
Slice=$(owner_slice "$owner")
TemporaryFileSystem=/srv/www /srv/jail /run/paddock
BindPaths=/srv/www/$id /run/paddock/fpm/$id
ReadWritePaths=/srv/www/$id /run/paddock/fpm/$id
ProtectProc=invisible
ProcSubset=pid
PrivateTmp=yes
PrivateIPC=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
RestrictSUIDSGID=yes
EOF
}

render_slice() {
	local mem_mb=${1:-2048} cpu=${2:-200} tasks=${3:-512}
	cat <<EOF
[Slice]
MemoryMax=$((mem_mb / 1024))G
CPUQuota=${cpu}%
TasksMax=$tasks
EOF
}

# §7.2. DefaultRuntimeDir is a PoC addition: httpd otherwise keeps mutexes in /run/httpd,
# which the vhost user cannot write. T0.3 confirms whether the specification needs it.
render_backend_httpd() {
	local n=$1 domain=$2 id addr
	id=$(vh_id "$n")
	addr=$(vh_addr "$n")
	local m
	for m in mpm_event unixd systemd authz_core authz_host authn_core authn_file auth_basic \
		authz_user access_compat alias dir mime log_config setenvif env headers expires \
		deflate filter rewrite remoteip proxy proxy_fcgi; do
		echo "LoadModule ${m}_module modules/mod_${m}.so"
	done
	cat <<EOF

ServerRoot /etc/httpd
DefaultRuntimeDir /run/paddock-httpd/$id
Listen $addr:81
PidFile /run/paddock-httpd/$id/httpd.pid
ErrorLog /srv/www/$id/logs/error.log
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
CustomLog /srv/www/$id/logs/access.log combined
TypesConfig /etc/mime.types
ServerName $domain
DocumentRoot /srv/www/$id/public
DirectoryIndex index.php index.html

RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 127.0.0.1
SetEnvIf X-Forwarded-Proto https HTTPS=on

<Directory />
    AllowOverride None
    Require all denied
</Directory>
<Directory /srv/www/$id/public>
    Options SymLinksIfOwnerMatch
    AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,SymLinksIfOwnerMatch
    Require all granted
</Directory>
<FilesMatch "\.php\$">
    SetHandler "proxy:unix:/run/paddock/fpm/$id/php.sock|fcgi://localhost"
</FilesMatch>
EOF
}

render_fpm() {
	local n=$1 max_children=${2:-10} id
	id=$(vh_id "$n")
	cat <<EOF
[global]
error_log = /srv/www/$id/logs/php-fpm.log
systemd_interval = 10

[$id]
listen = /run/paddock/fpm/$id/php.sock
listen.mode = 0600
pm = ondemand
pm.max_children = $max_children
pm.process_idle_timeout = 30s
pm.max_requests = 500
php_admin_value[open_basedir] = /srv/www/$id/
php_admin_value[upload_tmp_dir] = /srv/www/$id/tmp
php_admin_value[sys_temp_dir] = /srv/www/$id/tmp
php_admin_value[session.save_path] = /srv/www/$id/sessions
php_admin_value[error_log] = /srv/www/$id/logs/php-error.log
php_admin_value[pdo_mysql.default_socket] = /var/lib/mysql/mysql.sock
php_admin_value[mysqli.default_socket] = /var/lib/mysql/mysql.sock
php_admin_value[opcache.jit] = off
env[DB_HOST] = localhost
env[DB_SOCKET] = /var/lib/mysql/mysql.sock
env[DB_USER] = $id
EOF
}

# §7.4 with the PoC certificate in place of MDomain: test VMs have no public DNS for ACME.
render_front() {
	local n=$1 domain=$2 addr
	addr=$(vh_addr "$n")
	cat <<EOF
<VirtualHost *:80>
    ServerName $domain
    ServerAlias www.$domain
</VirtualHost>

<VirtualHost *:443>
    ServerName $domain
    ServerAlias www.$domain
    SSLEngine on
    SSLCertificateFile $POC_CERT
    SSLCertificateKeyFile $POC_KEY
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto https
    ProxyPass        / http://$addr:81/
    ProxyPassReverse / http://$addr:81/
</VirtualHost>
EOF
}

write_if_changed() {
	local dest=$1 tmp
	tmp=$(mktemp "$(dirname "$dest")/.tmp.XXXXXX")
	cat >"$tmp"
	if [[ -f $dest ]] && cmp -s "$tmp" "$dest"; then
		rm -f "$tmp"
		return 0
	fi
	chmod 0644 "$tmp"
	mv -f "$tmp" "$dest"
	restorecon "$dest" 2>/dev/null || true
}

# vh_create N OWNER PHP [DOMAIN] [DISK_MB] [START: yes|fpm|no]
# Creates the Linux user, tree, quota, rendered configs and units; starts FPM and backend.
vh_create() {
	local n=$1 owner=$2 php=$3 domain=${4:-} disk_mb=${5:-1024} start=${6:-yes}
	local id uid
	id=$(vh_id "$n")
	uid=$(vh_uid "$n")
	domain=${domain:-$id.test}
	CREATED_VHOSTS+=("$n")

	getent group "$id" >/dev/null || groupadd -g "$uid" "$id"
	# Subordinate ID ranges would overlap vhost UIDs (both start at 100000).
	getent passwd "$id" >/dev/null ||
		useradd -u "$uid" -g "$uid" -M -d "$WWW/$id" -s /sbin/nologin \
			-K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0 "$id"

	install -d -o "$id" -g "$id" -m 0700 "$WWW/$id"
	local d
	for d in private logs tmp sessions; do
		install -d -o "$id" -g "$id" -m 0700 "$WWW/$id/$d"
	done
	install -d -o "$id" -g "$id" -m 0750 "$WWW/$id/public"
	xfs_quota -x -c "project -s -p $WWW/$id $n" "$WWW" >/dev/null
	xfs_quota -x -c "limit -p bhard=${disk_mb}m $n" "$WWW"
	restorecon -RF "$WWW/$id"

	install -d -m 0755 "$ETC_PADDOCK/httpd" "$ETC_PADDOCK/fpm" "$ETC_PADDOCK/poc"
	echo "$php" >"$ETC_PADDOCK/poc/$id.php"
	echo "$owner" >"$ETC_PADDOCK/poc/$id.owner"
	render_backend_httpd "$n" "$domain" | write_if_changed "$ETC_PADDOCK/httpd/$id.conf"
	render_fpm "$n" | write_if_changed "$ETC_PADDOCK/fpm/$id.conf"

	touch "$TMPFILES"
	grep -q " $RUN_FPM/$id " "$TMPFILES" || echo "d $RUN_FPM/$id 0700 $id $id -" >>"$TMPFILES"
	systemd-tmpfiles --create "$TMPFILES"

	[[ -f $UNIT_DIR/$(owner_slice "$owner") ]] ||
		render_slice | write_if_changed "$UNIT_DIR/$(owner_slice "$owner")"
	local unit
	for unit in "$(httpd_unit "$n")" "$(fpm_unit "$n" "$php")"; do
		install -d -m 0755 "$UNIT_DIR/$unit.d"
		render_sandbox_dropin "$n" "$owner" | write_if_changed "$UNIT_DIR/$unit.d/10-sandbox.conf"
	done

	if [[ -n ${FRONT:-} ]]; then
		render_front "$n" "$domain" | write_if_changed "/etc/httpd/conf.d/paddock-$id.conf"
	fi

	systemctl daemon-reload
	if [[ $start != no ]]; then
		systemctl enable --now "$(fpm_unit "$n" "$php")"
		wait_for 20 test -S "$RUN_FPM/$id/php.sock"
	fi
	if [[ $start == yes ]]; then
		systemctl enable --now "$(httpd_unit "$n")"
		if [[ -n ${FRONT:-} ]]; then
			apachectl configtest
			systemctl reload httpd
		fi
	fi
}

vh_destroy() {
	local n=$1 id uid
	id=$(vh_id "$n")
	uid=$(vh_uid "$n")
	local v unit
	for v in "${PHP_VERSIONS[@]}"; do
		unit=$(fpm_unit "$n" "$v")
		systemctl disable --now "$unit" 2>/dev/null || true
		rm -rf "$UNIT_DIR/$unit.d"
	done
	unit=$(httpd_unit "$n")
	systemctl disable --now "$unit" 2>/dev/null || true
	rm -rf "$UNIT_DIR/$unit.d"

	jail_destroy "$n"

	if [[ -f /etc/httpd/conf.d/paddock-$id.conf ]]; then
		rm -f "/etc/httpd/conf.d/paddock-$id.conf"
		systemctl reload httpd 2>/dev/null || true
	fi
	if [[ -S $MYSQL_SOCK ]]; then
		local db
		for db in $(mysql -N -e "SHOW DATABASES LIKE '${id}\\_%'" 2>/dev/null); do
			mysql -e "DROP DATABASE \`$db\`"
		done
		mysql -e "DROP USER IF EXISTS '$id'@'localhost'" 2>/dev/null || true
	fi

	if mountpoint -q "$WWW"; then
		xfs_quota -x -c "limit -p bhard=0 $n" "$WWW" 2>/dev/null || true
		[[ -d $WWW/$id ]] && xfs_quota -x -c "project -C -p $WWW/$id $n" "$WWW" >/dev/null 2>&1 || true
	fi
	rm -rf "${WWW:?}/$id" "${RUN_FPM:?}/$id"
	rm -f "$ETC_PADDOCK/httpd/$id.conf" "$ETC_PADDOCK/fpm/$id.conf" \
		"$ETC_PADDOCK/poc/$id.php" "$ETC_PADDOCK/poc/$id.owner"
	[[ -f $TMPFILES ]] && sed -i "\# $RUN_FPM/$id #d" "$TMPFILES"
	systemctl unmask "user@$uid.service" 2>/dev/null || true
	rm -rf "$UNIT_DIR/user-$uid.slice.d" "/etc/ssh/authorized_keys/$id"
	pkill -KILL -u "$uid" 2>/dev/null || true
	getent passwd "$id" >/dev/null && userdel "$id"
	getent group "$id" >/dev/null && groupdel "$id"
	return 0
}

remove_owner_slice() {
	systemctl stop "$(owner_slice "$1")" 2>/dev/null || true
	rm -f "$UNIT_DIR/$(owner_slice "$1")"
}

# §7.5. jail_create N KIND (sftp|shell): mount units, sshd groups, user slice, masked user@.
mount_unit_name() { systemd-escape --path --suffix=mount "$1"; }

write_mount_unit() {
	local what=$1 where=$2 type=$3 options=$4 name
	name=$(mount_unit_name "$where")
	install -d "$where"
	cat <<EOF | write_if_changed "$UNIT_DIR/$name"
[Mount]
What=$what
Where=$where
Type=$type
Options=$options

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable --now "$name"
}

jail_create() {
	local n=$1 kind=$2 id uid j
	id=$(vh_id "$n")
	uid=$(vh_uid "$n")
	j=$JAIL/$id

	install -d -o root -g root -m 0755 "$JAIL" "$j" "$j/site"
	write_mount_unit "$WWW/$id" "$j/site" none bind

	if [[ $kind == shell ]]; then
		install -d -o root -g root -m 0755 "$j/usr" "$j/opt" "$j/opt/remi" "$j/opt/paddock/bin" \
			"$j/etc" "$j/dev" "$j/proc"
		install -d -o root -g root -m 1777 "$j/tmp"
		write_mount_unit /usr "$j/usr" none bind,ro,nosuid,nodev
		write_mount_unit /opt/remi "$j/opt/remi" none bind,ro,nosuid,nodev
		write_mount_unit proc "$j/proc" proc hidepid=invisible,subset=pid
		local l
		for l in bin sbin lib lib64; do ln -sfn "usr/$l" "$j/$l"; done

		getent passwd "$id" >"$j/etc/passwd"
		getent group "$id" >"$j/etc/group"
		cp -f /etc/resolv.conf /etc/ld.so.cache "$j/etc/"
		rm -rf "$j/etc/pki"
		cp -a /etc/pki "$j/etc/pki"
		printf 'export PATH=/opt/paddock/bin:/usr/local/bin:/usr/bin\nexport HOME=/site\ncd /site\n' \
			>"$j/etc/profile"
		local dev name type major minor
		for dev in "null c 1 3" "zero c 1 5" "urandom c 1 9" "tty c 5 0"; do
			read -r name type major minor <<<"$dev"
			[[ -e $j/dev/$name ]] || mknod -m 0666 "$j/dev/$name" "$type" "$major" "$minor"
		done
		ln -sfn "/opt/remi/php$(php_tag "$(vh_php "$n")")/root/usr/bin/php" "$j/opt/paddock/bin/php"
		usermod -s /bin/bash -G paddock-shell "$id"
	else
		usermod -G paddock-sftp "$id"
	fi
	restorecon -RF "$j" 2>/dev/null || true

	systemctl mask "user@$uid.service"
	install -d "$UNIT_DIR/user-$uid.slice.d"
	{
		echo "[Slice]"
		render_slice | tail -n +2
	} | write_if_changed "$UNIT_DIR/user-$uid.slice.d/limits.conf"
	systemctl daemon-reload
}

jail_destroy() {
	local n=$1 j unit sub
	j=$JAIL/$(vh_id "$n")
	[[ -d $j ]] || return 0
	for sub in proc opt/remi usr site; do
		unit=$(mount_unit_name "$j/$sub")
		systemctl disable --now "$unit" 2>/dev/null || true
		rm -f "$UNIT_DIR/$unit"
		mountpoint -q "$j/$sub" && umount -l "$j/$sub"
	done
	# Only remove the jail once nothing is mounted below it.
	if ! findmnt -rn -o TARGET | grep -q "^$j/"; then
		rm -rf --one-file-system "$j"
	fi
}

# Generates an SSH key for vhost N, installs it as an authorized key, and prints the key path.
ssh_key_for() {
	local n=$1 id key
	id=$(vh_id "$n")
	key=$POC_TMP/key-$id
	[[ -f $key ]] || ssh-keygen -q -t ed25519 -N '' -f "$key"
	install -d -m 0755 /etc/ssh/authorized_keys
	install -m 0644 "$key.pub" "/etc/ssh/authorized_keys/$id"
	restorecon -RF /etc/ssh/authorized_keys
	echo "$key"
}

ssh_as() {
	local key=$1 user=$2
	shift 2
	ssh -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-o LogLevel=ERROR -o ConnectTimeout=10 "$user@127.0.0.1" "$@"
}

remove_sshd_dropin() {
	rm -f /etc/ssh/sshd_config.d/50-paddock.conf
	systemctl reload sshd
}

install_sshd_dropin() {
	getent group paddock-sftp >/dev/null || groupadd -r paddock-sftp
	getent group paddock-shell >/dev/null || groupadd -r paddock-shell
	install -d -m 0755 /etc/ssh/authorized_keys
	cat <<'EOF' | write_if_changed /etc/ssh/sshd_config.d/50-paddock.conf
AuthorizedKeysFile /etc/ssh/authorized_keys/%u

Match Group paddock-sftp,paddock-shell
    ChrootDirectory /srv/jail/%u
    AllowTcpForwarding local
    PermitOpen 127.0.0.1:3306
    X11Forwarding no
    AllowAgentForwarding no

Match Group paddock-sftp
    ForceCommand internal-sftp -d /site
EOF
	sshd -t
	systemctl reload sshd
}

install_nft_rule() {
	install -d -m 0755 "$ETC_PADDOCK"
	cat <<'EOF' | write_if_changed "$ETC_PADDOCK/nftables.conf"
# Declaring and deleting the table first makes nft -f replace it in one transaction: the old
# rule stays in force until the new one is in place, and a file that fails to load changes nothing.
table inet paddock
delete table inet paddock

table inet paddock {
    chain output {
        type filter hook output priority 0; policy accept;
        ip daddr 127.64.0.0/16 tcp dport 81 meta skuid != "apache" reject
        ip daddr 127.0.0.1 tcp dport 81 meta skuid != "root" reject
    }
}
EOF
	cat <<'EOF' | write_if_changed "$UNIT_DIR/paddock-nft.service"
[Unit]
Description=Paddock loopback firewall rule
After=firewalld.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/paddock/nftables.conf
ExecReload=/usr/sbin/nft -f /etc/paddock/nftables.conf
ExecStop=/usr/sbin/nft delete table inet paddock

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable --now paddock-nft.service
	systemctl reload-or-restart paddock-nft.service
}

remove_nft_rule() {
	systemctl disable --now paddock-nft.service 2>/dev/null || true
	rm -f "$UNIT_DIR/paddock-nft.service" "$ETC_PADDOCK/nftables.conf"
	systemctl daemon-reload
}

# §7.6 kernel settings. Saves the current values so restore_sysctl can put them back.
readonly SYSCTL_FILE=/etc/sysctl.d/90-paddock.conf
SYSCTL_SAVED=()
apply_sysctl() {
	local settings=(kernel.dmesg_restrict=1 kernel.kptr_restrict=2 fs.protected_symlinks=1
		fs.protected_hardlinks=1 fs.protected_fifos=2 fs.protected_regular=2
		user.max_user_namespaces=0)
	local kv
	for kv in "${settings[@]}"; do
		SYSCTL_SAVED+=("${kv%%=*}=$(sysctl -n "${kv%%=*}")")
	done
	printf '%s\n' "${settings[@]/=/ = }" | write_if_changed "$SYSCTL_FILE"
	sysctl -q -p "$SYSCTL_FILE"
	on_cleanup restore_sysctl
}

restore_sysctl() {
	rm -f "$SYSCTL_FILE"
	local kv
	for kv in "${SYSCTL_SAVED[@]}"; do sysctl -q -w "$kv"; done
}

# §8 PHP switch: start the new FPM on the same socket path, then stop the old one.
vh_php_switch() {
	local n=$1 new=$2 old id unit newpid
	id=$(vh_id "$n")
	old=$(vh_php "$n")
	unit=$(fpm_unit "$n" "$new")
	install -d -m 0755 "$UNIT_DIR/$unit.d"
	render_sandbox_dropin "$n" "$(vh_owner "$n")" | write_if_changed "$UNIT_DIR/$unit.d/10-sandbox.conf"
	systemctl daemon-reload
	systemctl enable --now "$unit"
	newpid=$(systemctl show -p MainPID --value "$unit")
	wait_for 20 bash -c "ss -xlpn | grep -F '$RUN_FPM/$id/php.sock' | grep -q 'pid=$newpid,'" ||
		echo "new FPM $unit never owned the socket" >&2
	systemctl disable --now "$(fpm_unit "$n" "$old")"
	rm -rf "$UNIT_DIR/$(fpm_unit "$n" "$old").d"
	echo "$new" >"$ETC_PADDOCK/poc/$id.php"
	if [[ -L $JAIL/$id/opt/paddock/bin/php ]]; then
		ln -sfn "/opt/remi/php$(php_tag "$new")/root/usr/bin/php" "$JAIL/$id/opt/paddock/bin/php"
	fi
	systemctl daemon-reload
}

# Runs a command as vhost N's UID in the host namespaces, unconfined by systemd or SELinux.
# Separates DAC and firewall checks from the sandbox ones.
as_uid() {
	local n=$1
	shift
	setpriv --reuid="$(vh_uid "$n")" --regid="$(vh_uid "$n")" --clear-groups -- "$@"
}

php_cli() { echo "/opt/remi/php$(php_tag "$1")/root/usr/bin/php"; }

# §9 primary DB user and one database.
db_create_primary() {
	local n=$1 suffix=${2:-app} id
	id=$(vh_id "$n")
	local pw
	pw=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
	mysql <<EOF
CREATE DATABASE IF NOT EXISTS \`${id}_${suffix}\`;
CREATE USER IF NOT EXISTS '$id'@'localhost' IDENTIFIED VIA unix_socket OR mysql_native_password USING PASSWORD('$pw');
ALTER USER '$id'@'localhost' WITH MAX_USER_CONNECTIONS 20;
GRANT ALL ON \`${id}\\_${suffix}\`.* TO '$id'@'localhost';
EOF
}
