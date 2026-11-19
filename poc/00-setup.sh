#!/usr/bin/env bash
# T0.1 VM baseline. Idempotent.
# Usage: 00-setup.sh [--device /dev/vdb [--format]]
# Without --device, /srv/www is an XFS file on a loop device.
source "$(dirname "$0")/lib.sh"

DEVICE=
FORMAT=no
while [[ $# -gt 0 ]]; do
	case $1 in
	--device) DEVICE=$2 && shift 2 ;;
	--format) FORMAT=yes && shift ;;
	*) echo "unknown argument: $1" >&2 && exit 2 ;;
	esac
done

readonly LOOP_IMG=/var/lib/paddock-poc/www.img
readonly LOOP_SIZE=${POC_LOOP_SIZE:-8G}

poc_start

# shellcheck source=/dev/null
source /etc/os-release
if [[ ${ID:-} == almalinux && ${VERSION_ID%%.*} == 9 ]] &&
	[[ $(printf '%s\n' 9.4 "$VERSION_ID" | sort -V | head -1) == 9.4 ]]; then
	pass "OS is AlmaLinux $VERSION_ID"
else
	fail "OS must be AlmaLinux 9.4 or later, found ${PRETTY_NAME:-unknown}"
	exit 1
fi
if [[ $(getenforce) == Enforcing ]]; then pass "SELinux enforcing"; else fail "SELinux is $(getenforce)"; fi

rpm -q epel-release >/dev/null || dnf -y -q install epel-release
rpm -q remi-release >/dev/null || dnf -y -q install https://rpms.remirepo.net/enterprise/remi-release-9.rpm
if ! dnf -q module list --enabled mariadb 2>/dev/null | grep -q '10.11'; then
	dnf -y -q module reset mariadb
	dnf -y -q module enable mariadb:10.11
fi

packages=(httpd mod_ssl mod_md mariadb-server fail2ban nftables firewalld xfsprogs
	policycoreutils-python-utils openssh-server openssh-clients util-linux procps-ng curl tar)
for v in "${PHP_VERSIONS[@]}"; do
	t=$(php_tag "$v")
	packages+=("php$t-php-fpm" "php$t-php-cli" "php$t-php-mysqlnd" "php$t-php-opcache"
		"php$t-php-gd" "php$t-php-mbstring" "php$t-php-xml" "php$t-php-intl" "php$t-php-pecl-zip")
done
missing=()
for p in "${packages[@]}"; do rpm -q "$p" >/dev/null 2>&1 || missing+=("$p"); done
[[ ${#missing[@]} -eq 0 ]] || dnf -y -q install "${missing[@]}"
pass "packages installed"
info "versions: $(rpm -q --qf '%{NAME}-%{VERSION} ' httpd mariadb-server systemd php83-php-fpm php84-php-fpm)"

# /srv/www with project quotas.
install -d -m 0755 /srv
if [[ -n $DEVICE ]]; then
	if [[ -z $(blkid -o value -s TYPE "$DEVICE" 2>/dev/null) ]]; then
		if [[ $FORMAT != yes ]]; then
			fail "$DEVICE is empty; rerun with --format to create XFS on it"
			exit 1
		fi
		mkfs.xfs -q "$DEVICE"
	fi
	[[ $(blkid -o value -s TYPE "$DEVICE") == xfs ]] || { fail "$DEVICE is not XFS" && exit 1; }
	fstab_src="UUID=$(blkid -o value -s UUID "$DEVICE")"
	fstab_opts=prjquota
else
	install -d -m 0700 "$(dirname "$LOOP_IMG")"
	if [[ ! -f $LOOP_IMG ]]; then
		truncate -s "$LOOP_SIZE" "$LOOP_IMG"
		mkfs.xfs -q "$LOOP_IMG"
	fi
	fstab_src=$LOOP_IMG
	fstab_opts=loop,prjquota
fi
install -d -m 0711 "$WWW"
if ! grep -qE "[[:space:]]${WWW}[[:space:]]" /etc/fstab; then
	echo "$fstab_src $WWW xfs $fstab_opts 0 0" >>/etc/fstab
	systemctl daemon-reload
fi
mountpoint -q "$WWW" || mount "$WWW"
chmod 0711 "$WWW"
chown root:root "$WWW"
install -d -o root -g root -m 0755 "$JAIL"

if ! semanage fcontext -l -C | grep -qF '/srv/www(/.*)?'; then
	semanage fcontext -a -t httpd_sys_rw_content_t '/srv/www(/.*)?'
fi
restorecon -RF "$WWW"

if xfs_quota -x -c state "$WWW" | grep -A2 '^Project quota state' | grep -q 'Accounting: ON' &&
	xfs_quota -x -c state "$WWW" | grep -A2 '^Project quota state' | grep -q 'Enforcement: ON'; then
	pass "project quota accounting and enforcement on for $WWW"
else
	fail "project quota not on for $WWW"
	xfs_quota -x -c state "$WWW" | sed 's/^/     /'
fi
check "$WWW labelled httpd_sys_rw_content_t" bash -c "ls -dZ $WWW | grep -q httpd_sys_rw_content_t"

cat <<'EOF' | write_if_changed /etc/my.cnf.d/paddock.cnf
[mysqld]
bind-address=127.0.0.1
EOF
systemctl enable --now mariadb firewalld httpd
check "MariaDB socket at $MYSQL_SOCK" wait_for 20 test -S "$MYSQL_SOCK"
check "MariaDB root uses unix_socket" bash -c \
	"mysql -N -e \"SELECT priv FROM mysql.global_priv WHERE User='root' AND Host='localhost'\" | grep -q unix_socket"
check "front certificate $POC_CERT exists" test -s "$POC_CERT"


getent group paddock-sftp >/dev/null || groupadd -r paddock-sftp
install_unit_templates
pass "unit templates installed"

info "systemd $(systemctl --version | head -1 | awk '{print $2}')"
