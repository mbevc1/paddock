#!/usr/bin/env bash
# T0.9 Kernel settings (§7.6): T0.2 to T0.8 must still pass with them applied.
source "$(dirname "$0")/lib.sh"
poc_start
apply_sysctl

check "user.max_user_namespaces is 0" test "$(sysctl -n user.max_user_namespaces)" = 0
for script in 02-sandbox.sh 03-backend.sh 04-fpm-switch.sh 05-mariadb.sh 06-loopback.sh 07-sftp.sh 08-shell.sh; do
	if "$POC_DIR/$script" 2>&1 | sed 's/^/     /'; then
		pass "$script passes with the kernel settings"
	else
		fail "$script fails with the kernel settings"
	fi
done
