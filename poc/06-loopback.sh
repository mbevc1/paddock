#!/usr/bin/env bash
# T0.6 Loopback rule (§7.6): only the apache UID reaches backends on 127.64.0.0/16:81.
source "$(dirname "$0")/lib.sh"
poc_start
install_unit_templates

vh_create 1 1 8.3
vh_create 2 2 8.3
on_cleanup "remove_owner_slice 1"
on_cleanup "remove_owner_slice 2"
echo b-ok >"$WWW/v00002/public/hello.txt"
chown v00002:v00002 "$WWW/v00002/public/hello.txt"

# A as a plain process, so only the firewall decides.
a_curl() { as_uid 1 curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$(vh_addr 2):81/hello.txt"; }
check "baseline: without the rule A reaches B's backend" test "$(a_curl)" = 200

install_nft_rule
on_cleanup remove_nft_rule

checks() {
	local when=$1 r
	check "$when: apache reaches B's backend" test "$(backend_get 2 /hello.txt)" = b-ok
	refute "$when: A (plain process) cannot reach B's backend" test "$(a_curl)" = 200
	refute "$when: root cannot reach B's backend" curl -sf -m 5 "http://$(vh_addr 2):81/hello.txt"
	r=$(php_eval 1 "\$f = @fsockopen('$(vh_addr 2)', 81, \$e, \$s, 3); echo \$f ? 'OPEN' : \"BLOCKED \$e \$s\";")
	check "$when: A's PHP cannot reach B's backend ($r)" grep -q '^BLOCKED' <<<"$r"
}
checks "after load"
firewall-cmd -q --reload
check "table inet paddock survives firewall-cmd --reload" nft list table inet paddock
checks "after firewalld reload"
rules() { nft list chain inet paddock output | grep -c reject; }
systemctl restart paddock-nft.service
check "restart leaves exactly one rule" test "$(rules)" = 1
systemctl reload paddock-nft.service
check "reload leaves exactly one rule" test "$(rules)" = 1
cp "$ETC_PADDOCK/nftables.conf" "$ETC_PADDOCK/nftables.conf.good"
sed -i 's/ reject$/ rejekt/' "$ETC_PADDOCK/nftables.conf"
refute "reload of a broken file fails" systemctl reload paddock-nft.service
check "the old rule stays after a failed reload" test "$(rules)" = 1
mv -f "$ETC_PADDOCK/nftables.conf.good" "$ETC_PADDOCK/nftables.conf"
checks "after a failed reload"
