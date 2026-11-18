#!/usr/bin/env bash
# T0.7 SFTP jail (§7.5): chroot to /site, forwarding only to 127.0.0.1:3306.
source "$(dirname "$0")/lib.sh"
poc_start
install_unit_templates

vh_create 1 1 8.3
on_cleanup "remove_owner_slice 1"
id=$(vh_id 1)
install_sshd_dropin
on_cleanup remove_sshd_dropin
jail_create 1 sftp
key=$(ssh_key_for 1)

check "jail mount unit active" systemctl is-active "$(mount_unit_name "$JAIL/$id/site")"
sftp_batch() {
	sftp -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-o LogLevel=ERROR -b - "$id@127.0.0.1"
}

out=$(printf 'pwd\nls -a /\n' | sftp_batch 2>&1) || true
info "sftp output: $(tr '\n' ' ' <<<"$out")"
check "SFTP starts in /site" grep -q 'Remote working directory: /site' <<<"$out"
check "SFTP root lists only site" test \
	"$(printf 'ls -1a /\n' | sftp_batch 2>/dev/null | grep -v '^sftp>' | grep -vxE '\.|\.\.' | tr '\n' ' ')" = "site "
printf 'put /etc/hostname /site/public/uploaded.txt\n' | sftp_batch >/dev/null 2>&1 || true
check "uploaded file belongs to $id" test "$(stat -c %U "$WWW/$id/public/uploaded.txt" 2>/dev/null)" = "$id"
out=$(ssh_as "$key" "$id" id 2>&1) || true
refute "no shell for SFTP accounts" grep -q uid= <<<"$out"

# forward LOCAL_PORT TARGET: prints the first bytes a client reads through the tunnel.
forward() {
	local port=$1 target=$2 pid out
	ssh -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-o LogLevel=ERROR -o ExitOnForwardFailure=yes -N -L "127.0.0.1:$port:$target" "$id@127.0.0.1" &
	pid=$!
	wait_for 20 bash -c "ss -ltnH 'sport = :$port' | grep -q ."
	out=$(timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port; timeout 3 head -c 200 <&3" 2>/dev/null | tr -c '[:print:]' '.') || true
	kill "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null || true
	echo "$out"
}
out=$(forward 13306 127.0.0.1:3306)
check "forwarding to 127.0.0.1:3306 reaches MariaDB ($out)" grep -qi mariadb <<<"$out"
out=$(forward 13307 127.0.0.1:22)
check "forwarding to 127.0.0.1:22 is refused" test -z "$out"
out=$(forward 13308 "$(vh_addr 1):81")
check "forwarding to the backend is refused" test -z "$out"
