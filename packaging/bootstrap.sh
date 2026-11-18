#!/usr/bin/env bash
# Prepares an AlmaLinux 9.4+ host for Paddock and installs it (§14.3). Runs as root; safe to rerun.
# Usage: bootstrap.sh --hostname NAME [--www-device DEV [--format]] [--email ADDR] [--admin NAME]
#                     [--rpm FILE]
set -euo pipefail

# The release workflow replaces @OWNER@; --rpm installs a local package instead of the repository.
readonly OWNER='@OWNER@'
readonly REPO_FILE=/etc/yum.repos.d/paddock.repo
readonly REMI_RELEASE_URL=https://rpms.remirepo.net/enterprise/remi-release-9.rpm
# Primary key fingerprints Remi signs remi-release-9 with, checked against the keys the package
# carries before rpm trusts any of them. Remi rotates keys; add the new fingerprint when
# remi-release-9 is signed with another key.
readonly REMI_FINGERPRINTS=(
	B1ABF71E14C9D74897E198A8B19527F1478F8947 # Remi's RPM repository (EL 9), created 2021-01-04
)

readonly WWW=/srv/www
readonly JAIL=/srv/jail
readonly MARKER=$WWW/.paddock
readonly SHARE=/usr/share/paddock/etc
readonly KEEP='# paddock: keep'
readonly MODULES_CONF=/etc/httpd/conf.modules.d/00-base.conf
readonly STATUS_LINE='LoadModule status_module modules/mod_status.so'
readonly PANEL_CERT=/var/lib/paddock/web/panel.crt
readonly PORTS=(80 443 8080 8443)

HOSTNAME_ARG=
DEVICE=
FORMAT=no
EMAIL=
ADMIN='admin'
LOCAL_RPM=
CHANGED=()
WORK=

die() {
	echo "bootstrap: $*" >&2
	exit 1
}
step() { echo "==> $*"; }

usage() {
	sed -n '3,4s/^# //p' "$0"
	exit 2
}

# valid_hostname accepts lowercase ASCII DNS names with at least two labels; IDNs go in as
# punycode.
valid_hostname() {
	local h=$1
	[[ ${#h} -le 253 ]] &&
		[[ $h =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] &&
		[[ ! $h =~ \.[0-9]+$ ]]
}

valid_email() {
	local local_part=${1%@*} domain=${1#*@}
	[[ $1 == *@* && ${#1} -le 254 && $local_part =~ ^[A-Za-z0-9._%+-]{1,64}$ ]] && valid_hostname "$domain"
}

valid_admin() { [[ $1 =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }

valid_device() { [[ $1 =~ ^/dev/[A-Za-z0-9/_-]+$ && $1 != *..* ]]; }

# version_at_least returns true when $1 >= $2 in dotted numeric order.
version_at_least() { [[ $(printf '%s\n' "$2" "$1" | sort -V | head -1) == "$2" ]]; }

# port_users prints the program names `ss -ltnp` reports for a listening port.
port_users() { ss -H -ltnp "sport = :$1" | grep -o '"[^"]*",pid=' | sed 's/^"//; s/",pid=$//' | sort -u; }

# install_file writes SRC to DST only when the content differs and DST does not carry the keep
# marker, through a temporary file in DST's directory. With HOST set, @HOSTNAME@ becomes HOST.
install_file() {
	local src=$1 dst=$2 host=${3:-} tmp
	if [[ -f $dst ]] && grep -qF "$KEEP" "$dst"; then
		echo "    keeping local $dst"
		return
	fi
	install -d -m 0755 "$(dirname "$dst")"
	tmp=$(mktemp "$dst.XXXXXX")
	if [[ -n $host ]]; then
		sed "s/@HOSTNAME@/$host/g" "$src" >"$tmp"
	else
		cat "$src" >"$tmp"
	fi
	chmod 0644 "$tmp"
	if [[ -f $dst ]] && cmp -s "$tmp" "$dst"; then
		rm -f "$tmp"
		return
	fi
	mv -f "$tmp" "$dst"
	restorecon -F "$dst" 2>/dev/null || true
	CHANGED+=("$dst")
	echo "    wrote $dst"
}

# install_text writes TEXT to DST like install_file.
install_text() {
	local text=$1 dst=$2 src
	src=$(mktemp -p "$WORK")
	printf '%s\n' "$text" >"$src"
	install_file "$src" "$dst"
}

changed() {
	local f
	for f in "${CHANGED[@]}"; do [[ $f == "$1"* ]] && return 0; done
	return 1
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case $1 in
		--hostname) HOSTNAME_ARG=${2:-} && shift 2 ;;
		--www-device) DEVICE=${2:-} && shift 2 ;;
		--format) FORMAT=yes && shift ;;
		--email) EMAIL=${2:-} && shift 2 ;;
		--admin) ADMIN=${2:-} && shift 2 ;;
		--rpm) LOCAL_RPM=${2:-} && shift 2 ;;
		-h | --help) usage ;;
		*) die "unknown argument: $1" ;;
		esac
	done
	HOSTNAME_ARG=${HOSTNAME_ARG,,}
	valid_hostname "$HOSTNAME_ARG" || die "--hostname must be a DNS name such as panel.example.com"
	[[ -z $EMAIL ]] || valid_email "$EMAIL" || die "--email is not a valid address"
	valid_admin "$ADMIN" || die "--admin must match ^[a-z][a-z0-9_-]{0,31}$"
	[[ -z $DEVICE ]] || valid_device "$DEVICE" || die "--www-device must be a /dev path"
	[[ -z $LOCAL_RPM || -f $LOCAL_RPM ]] || die "--rpm $LOCAL_RPM does not exist"
	if [[ -z $LOCAL_RPM && $OWNER == @*@ ]]; then
		die "this copy has no repository owner; use the release asset or give --rpm"
	fi
}

check_host() {
	[[ $(id -u) -eq 0 ]] || die "run as root"
	# shellcheck source=/dev/null
	source /etc/os-release
	if [[ ${ID:-} != almalinux || ${VERSION_ID%%.*} != 9 ]] || ! version_at_least "$VERSION_ID" 9.4; then
		die "needs AlmaLinux 9.4 or later, found ${PRETTY_NAME:-unknown}"
	fi
	[[ $(getenforce) == Enforcing ]] || die "SELinux must be enforcing"
}

# key_pinned succeeds when KEY's primary fingerprint is one of the given fingerprints.
key_pinned() {
	local key=$1 fpr
	shift
	fpr=$(GNUPGHOME=$WORK gpg --batch --with-colons --show-keys "$key" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')
	[[ -n $fpr ]] && printf '%s\n' "$@" | grep -qxF "$fpr"
}

# install_remi trusts only keys inside remi-release whose fingerprint is pinned, then requires
# the package's signature to verify against them.
install_remi() {
	rpm -q remi-release >/dev/null 2>&1 && return
	[[ ${#REMI_FINGERPRINTS[@]} -gt 0 ]] || die "no Remi key fingerprint is pinned in this script"
	local dir=$WORK/remi key trusted=no
	mkdir -p "$dir"
	curl -fsSL --proto '=https' -o "$dir/remi-release.rpm" "$REMI_RELEASE_URL"
	(cd "$dir" && rpm2cpio remi-release.rpm | cpio -idm --quiet './etc/pki/rpm-gpg/*')
	for key in "$dir"/etc/pki/rpm-gpg/RPM-GPG-KEY-remi*; do
		[[ -f $key ]] || continue
		if key_pinned "$key" "${REMI_FINGERPRINTS[@]}"; then
			rpm --import "$key"
			trusted=yes
		fi
	done
	[[ $trusted == yes ]] || die "remi-release carries no key with a pinned fingerprint"
	rpm --checksig "$dir/remi-release.rpm" | grep -q 'signatures OK' ||
		die "remi-release is not signed by a pinned key"
	dnf -y -q install "$dir/remi-release.rpm"
}

install_packages() {
	step "installing repositories and Paddock"
	rpm -q epel-release >/dev/null 2>&1 || dnf -y -q install epel-release
	install_remi
	if ! dnf -q module list --enabled mariadb 2>/dev/null | grep -q '10\.11'; then
		dnf -y -q module reset mariadb
		dnf -y -q module enable mariadb:10.11
	fi
	if [[ -n $LOCAL_RPM ]]; then
		dnf -y -q install "$LOCAL_RPM" firewalld
		return
	fi
	install_text "[paddock]
name=Paddock
baseurl=https://${OWNER,,}.github.io/paddock/el\$releasever/\$basearch/
enabled=1
# Unsigned until package signing (T2.9).
gpgcheck=0
repo_gpgcheck=0" "$REPO_FILE"
	dnf -y -q install paddock firewalld
}

check_ports() {
	step "checking ports"
	local port user
	for port in "${PORTS[@]}"; do
		while read -r user; do
			[[ -z $user || $user == httpd || $user == paddock ]] || die "port $port is in use by $user"
		done < <(port_users "$port")
	done
}

# check_www refuses a /srv/www holding anything but the marker and vhost directories.
check_www() {
	local entry name has_marker=no others=()
	for entry in "$WWW"/* "$WWW"/.[!.]*; do
		[[ -e $entry ]] || continue
		name=${entry##*/}
		if [[ $entry == "$MARKER" ]]; then
			has_marker=yes
		elif [[ ! $name =~ ^v[0-9]{5}$ ]]; then
			others+=("$name")
		fi
	done
	if [[ $has_marker == no ]] && [[ -n $(ls -A "$WWW") ]]; then
		die "$WWW holds data Paddock did not create; refusing to continue"
	fi
	[[ ${#others[@]} -eq 0 ]] || die "$WWW holds unexpected entries: ${others[*]}"
}

prepare_www() {
	step "preparing $WWW"
	install -d -m 0711 "$WWW"
	if ! mountpoint -q "$WWW"; then
		check_www
		[[ -n $DEVICE ]] || die "$WWW is not mounted; give --www-device"
		[[ -b $DEVICE ]] || die "$DEVICE is not a block device"
		local fstype uuid
		fstype=$(blkid -o value -s TYPE "$DEVICE" || true)
		if [[ -z $fstype ]]; then
			[[ $FORMAT == yes ]] || die "$DEVICE is empty; rerun with --format to create XFS on it"
			mkfs.xfs -q "$DEVICE"
		elif [[ $fstype != xfs ]]; then
			die "$DEVICE holds $fstype, not XFS; refusing to format it"
		fi
		uuid=$(blkid -o value -s UUID "$DEVICE")
		[[ $uuid =~ ^[0-9a-fA-F-]{8,64}$ ]] || die "$DEVICE has no usable UUID"
		if ! grep -qE "^[^#[:space:]]+[[:space:]]+${WWW}[[:space:]]" /etc/fstab; then
			echo "UUID=$uuid $WWW xfs prjquota 0 0" >>/etc/fstab
			systemctl daemon-reload
		fi
		mount "$WWW"
	fi
	local fs opts
	read -r fs opts < <(findmnt -n -o FSTYPE,OPTIONS "$WWW")
	[[ $fs == xfs && ($opts == *prjquota* || $opts == *pquota*) ]] ||
		die "$WWW must be XFS mounted with prjquota, found $fs $opts"
	check_www
	[[ -e $MARKER ]] || install -m 0600 /dev/null "$MARKER"
	chown root:root "$WWW"
	chmod 0711 "$WWW"
	install -d -o root -g root -m 0755 "$JAIL"
	if ! semanage fcontext -l -C | grep -qF "$WWW(/.*)?"; then
		semanage fcontext -a -t httpd_sys_rw_content_t "$WWW(/.*)?"
	fi
	restorecon -R "$WWW"
}

install_configs() {
	step "installing host configuration"
	local src rel
	while IFS= read -r -d '' src; do
		rel=${src#"$SHARE"}
		if [[ $rel == /httpd/conf.d/paddock-01-panel.conf ]]; then
			install_file "$src" "/etc$rel" "$HOSTNAME_ARG"
		else
			install_file "$src" "/etc$rel"
		fi
	done < <(find "$SHARE" -type f -print0 | sort -z)
	if [[ -n $EMAIL ]]; then
		install_text "MDContactEmail $EMAIL" /etc/httpd/conf.d/paddock-00-contact.conf
	fi
	install_text "PADDOCK_HOSTNAME=$HOSTNAME_ARG
PADDOCK_ACME_EMAIL=$EMAIL" /etc/paddock/web.env
	if [[ -f $MODULES_CONF ]] && grep -qxF "$STATUS_LINE" "$MODULES_CONF"; then
		sed -i "s|^$STATUS_LINE\$|# Disabled by Paddock: $STATUS_LINE|" "$MODULES_CONF"
		CHANGED+=("$MODULES_CONF")
	fi
	sysctl -q -p /etc/sysctl.d/90-paddock.conf
}

configure_mariadb() {
	step "configuring MariaDB"
	systemctl enable -q --now mariadb.service
	if changed /etc/my.cnf.d/; then systemctl restart mariadb.service; fi
	mariadb -N -e "SELECT priv FROM mysql.global_priv WHERE User = 'root' AND Host = 'localhost'" |
		grep -q unix_socket || die "MariaDB root does not authenticate with unix_socket"
}

enable_services() {
	step "enabling services and firewall"
	systemctl enable -q --now firewalld.service
	firewall-cmd -q --permanent --add-service=http --add-service=https --add-port=8080/tcp --add-port=8443/tcp
	firewall-cmd -q --reload
	systemctl enable -q --now paddock-nft.service fail2ban.service
	if changed /etc/paddock/nftables.conf; then systemctl restart paddock-nft.service; fi
	if changed /etc/fail2ban/; then systemctl restart fail2ban.service; fi
	apachectl configtest
	systemctl enable -q --now httpd.service
	systemctl reload httpd.service
	sshd -t
	systemctl reload sshd.service
}

start_paddock() {
	step "creating Paddock's databases"
	paddock setup --admin "$ADMIN"
	step "starting Paddock"
	systemctl enable -q --now paddock-agent.service paddock-web.service
	local i
	for ((i = 0; i < 30; i++)); do
		[[ -s $PANEL_CERT ]] && break
		sleep 1
	done
	[[ -s $PANEL_CERT ]] || die "paddock-web did not create its certificate; see journalctl -u paddock-web"
	echo
	echo "Paddock is ready at https://$HOSTNAME_ARG:8443/"
	echo "Panel certificate $(openssl x509 -in "$PANEL_CERT" -noout -fingerprint -sha256)"
}

main() {
	parse_args "$@"
	check_host
	WORK=$(mktemp -d)
	trap 'rm -rf "$WORK"' EXIT
	install_packages
	check_ports
	prepare_www
	install_configs
	configure_mariadb
	enable_services
	start_paddock
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	main "$@"
fi
