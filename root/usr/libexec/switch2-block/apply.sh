#!/bin/sh
# Switch 2 Connection Spoof & Update Blocker core management script
. /lib/functions.sh
exec 9>/var/lock/switch2-block.lock
flock -x 9

CONF="switch2-block"
CGI_DIR="/www_nintendo/cgi-bin"
CGI_FILE="$CGI_DIR/ctest"
FW_USER="/etc/firewall.user"
NFT_D_FILE="/etc/nftables.d/99-switch2-block.nft"

log_msg() {
	logger -t "switch2-block" "$1"
}

is_fw4() {
	[ -x /sbin/fw4 ] || command -v fw4 >/dev/null 2>&1 || command -v nft >/dev/null 2>&1
}

# 动态探测当前路由器真实 LAN IP（消除任何硬编码 IP）
detect_lan_ip() {
	local ip
	ip=$(uci -q get network.lan.ipaddr | awk '{print $1}' | awk -F'/' '{print $1}')
	if [ -z "$ip" ]; then
		ip=$(ip -4 addr show br-lan 2>/dev/null | awk '/inet / {print $2}' | cut -d'/' -f1 | head -n1)
	fi
	echo "$ip"
}

# 根据主 LAN IP 动态推导同网段伪装辅助 IP（若主 IP 已为 .254 则避让为 .253）
derive_spoof_ip() {
	local lan_ip="$1"
	[ -z "$lan_ip" ] && return
	local prefix last_octet
	prefix=$(echo "$lan_ip" | awk -F'.' '{print $1"."$2"."$3}')
	last_octet=$(echo "$lan_ip" | awk -F'.' '{print $4}')
	if [ "$last_octet" = "254" ]; then
		echo "${prefix}.253"
	else
		echo "${prefix}.254"
	fi
}

# 幂等辅助函数：仅当值不同时才写入 UCI
uci_set_if_diff() {
	local cfg="$1" sec="$2" opt="$3" val="$4"
	local cur
	cur=$(uci -q get "${cfg}.${sec}.${opt}")
	[ "$cur" != "$val" ] && uci set "${cfg}.${sec}.${opt}=${val}"
}

# 幂等辅助函数：按换行符逐行精确比对 list，防止含空格选项被拆分导致重复写入
uci_add_list_unique() {
	local cfg="$1" sec="$2" opt="$3" val="$4"
	local existing old_ifs="$IFS"
	existing=$(uci -q -d '
' get "${cfg}.${sec}.${opt}" 2>/dev/null)
	IFS='
'
	for item in $existing; do
		if [ "$item" = "$val" ]; then
			IFS="$old_ifs"
			return 1
		fi
	done
	IFS="$old_ifs"
	uci add_list "${cfg}.${sec}.${opt}=${val}"
	return 0
}

ensure_cgi() {
	mkdir -p "$CGI_DIR"
	if [ ! -f "$CGI_FILE" ] || ! grep -q "X-Organization: Nintendo" "$CGI_FILE"; then
		cat << 'EOF' > "$CGI_FILE"
#!/bin/sh
printf "Status: 200 OK\r\n"
printf "Content-Type: text/plain\r\n"
printf "Content-Length: 2\r\n"
printf "X-Organization: Nintendo\r\n"
printf "\r\n"
printf "ok"
EOF
		chmod +x "$CGI_FILE"
	fi
}

cleanup_network() {
	if uci -q get network.nintendo >/dev/null; then
		uci -q delete network.nintendo
		uci commit network
	fi
	if [ "$(uci -q get firewall._switch2_zone_managed)" = "1" ]; then
		local i=0
		while uci -q get firewall.@zone[$i] >/dev/null; do
			if [ "$(uci -q get firewall.@zone[$i].name)" = "lan" ]; then
				uci -q del_list firewall.@zone[$i].network='nintendo'
			fi
			i=$((i + 1))
		done
		uci -q delete firewall._switch2_zone_managed
		uci commit firewall
	fi
}

cleanup_dhcp() {
	local lan_ip="$1"
	local old_lan_ip
	old_lan_ip="$(uci -q get dhcp.main_dns._sw2_lan_ip)"
	[ -z "$old_lan_ip" ] && old_lan_ip="$lan_ip"

	uci -q delete dhcp.nintendo_dns
	uci -q delete dhcp.switch2

	local guard=0
	while [ $guard -lt 100 ] && uci -q show dhcp | grep -q "dhcp\.@host\[[0-9]*\]\.tag='switch2'"; do
		local idx
		idx=$(uci -q show dhcp | grep "dhcp\.@host\[[0-9]*\]\.tag='switch2'" | head -n1 | sed -E 's/.*@host\[([0-9]+)\].*/\1/')
		if [ -n "$idx" ]; then
			uci -q delete dhcp.@host[$idx] || break
		else
			break
		fi
		guard=$((guard + 1))
	done

	if [ "$(uci -q get dhcp.main_dns._switch2_managed)" = "1" ]; then
		[ "$(uci -q get dhcp.main_dns._sw2_add_lan)" = "1" ] && [ -n "$old_lan_ip" ] && uci -q del_list dhcp.main_dns.listen_address="$old_lan_ip"
		[ "$(uci -q get dhcp.main_dns._sw2_add_lo_ip)" = "1" ] && uci -q del_list dhcp.main_dns.listen_address='127.0.0.1'
		[ "$(uci -q get dhcp.main_dns._sw2_add_lo_if)" = "1" ] && uci -q del_list dhcp.main_dns.interface='loopback'
		[ "$(uci -q get dhcp.main_dns._sw2_add_bind)" = "1" ] && uci -q delete dhcp.main_dns.bind_interfaces
		uci -q delete dhcp.main_dns._sw2_lan_ip
		uci -q delete dhcp.main_dns._sw2_add_lan
		uci -q delete dhcp.main_dns._sw2_add_lo_ip
		uci -q delete dhcp.main_dns._sw2_add_lo_if
		uci -q delete dhcp.main_dns._sw2_add_bind
		uci -q delete dhcp.main_dns._switch2_managed
	fi

	if [ "$(uci -q get dhcp.lan._switch2_managed)" = "1" ]; then
		uci -q delete dhcp.lan.instance
		uci -q delete dhcp.lan._switch2_managed
	fi

	if [ "$(uci -q get dhcp.lan._switch2_force_managed)" = "1" ]; then
		uci -q delete dhcp.lan.force
		uci -q delete dhcp.lan._switch2_force_managed
	fi
	uci commit dhcp
}
cleanup_uhttpd() {
	uci -q delete uhttpd.nintendo_ctest
	if [ "$(uci -q get uhttpd.main._switch2_managed)" = "1" ]; then
		local orig_list orig_redir
		orig_list=$(uci -q get uhttpd.main._sw2_orig_listen)
		orig_redir=$(uci -q get uhttpd.main._sw2_orig_redir)
		uci -q delete uhttpd.main.listen_http
		if [ -n "$orig_list" ]; then
			for item in $orig_list; do
				uci add_list uhttpd.main.listen_http="$item"
			done
		else
			uci add_list uhttpd.main.listen_http='0.0.0.0:80'
			uci add_list uhttpd.main.listen_http='[::]:80'
		fi
		if [ -n "$orig_redir" ]; then
			uci set uhttpd.main.redirect_https="$orig_redir"
		fi
		uci -q delete uhttpd.main._sw2_orig_listen
		uci -q delete uhttpd.main._sw2_orig_redir
		uci -q delete uhttpd.main._switch2_managed
	fi
	uci commit uhttpd
	rm -rf /www_nintendo
}

cleanup_firewall() {
	if [ -f "$FW_USER" ]; then
		if grep -q "^# BEGIN SWITCH2-BLOCK$" "$FW_USER" && grep -q "^# END SWITCH2-BLOCK$" "$FW_USER"; then
			sed -i '/^# BEGIN SWITCH2-BLOCK$/,/^# END SWITCH2-BLOCK$/d' "$FW_USER"
		fi
		sed -i '/Block_Switch2_IPv6_Input/d' "$FW_USER"
		sed -i '/Block_Switch2_All_Forward/d' "$FW_USER"
	fi

	if uci -q get firewall.switch2_fw_user >/dev/null; then
		uci -q delete firewall.switch2_fw_user
		uci commit firewall
	fi

	rm -f "$NFT_D_FILE"

	if is_fw4; then
		for chain in input forward; do
			local handles
			handles=$(nft -a list chain inet fw4 $chain 2>/dev/null | grep -E "Block_Switch2_(IPv6_Input|All_Forward)" | awk '{print $NF}')
			for h in $handles; do
				nft delete rule inet fw4 $chain handle "$h" 2>/dev/null
			done
		done
		nft delete chain inet fw4 switch2_block_input 2>/dev/null
		nft delete chain inet fw4 switch2_block_forward 2>/dev/null
	else
		if command -v ip6tables >/dev/null 2>&1; then
			ip6tables -S INPUT 2>/dev/null | grep "Block_Switch2_IPv6_Input" | sed 's/^-A /-D /' | while read -r rule; do
				ip6tables $rule 2>/dev/null
			done
			ip6tables -S FORWARD 2>/dev/null | grep "Block_Switch2_All_Forward" | sed 's/^-A /-D /' | while read -r rule; do
				ip6tables $rule 2>/dev/null
			done
		fi
		if command -v iptables >/dev/null 2>&1; then
			iptables -S FORWARD 2>/dev/null | grep "Block_Switch2_All_Forward" | sed 's/^-A /-D /' | while read -r rule; do
				iptables $rule 2>/dev/null
			done
		fi
	fi
}

apply_network() {
	local spoof_ip="$1"
	if [ "$(uci -q get network.nintendo)" != "interface" ]; then
		uci set network.nintendo='interface'
	fi
	uci_set_if_diff network nintendo proto 'static'
	uci_set_if_diff network nintendo device 'br-lan'
	if [ "$(uci -q get network.nintendo.ipaddr)" != "${spoof_ip}/24" ]; then
		uci -q delete network.nintendo.ipaddr
		uci add_list network.nintendo.ipaddr="${spoof_ip}/24"
	fi
	uci commit network

	local i=0
	while uci -q get firewall.@zone[$i] >/dev/null; do
		if [ "$(uci -q get firewall.@zone[$i].name)" = "lan" ]; then
			uci_add_list_unique firewall "@zone[$i]" network 'nintendo'
		fi
		i=$((i + 1))
	done
	uci_set_if_diff firewall _switch2_zone_managed '1'
	uci commit firewall
}

apply_dhcp() {
	local lan_ip="$1"
	local spoof_ip="$2"
	local domains="$3"
	local force_dhcp="$4"

	if ! uci -q get dhcp.main_dns >/dev/null; then
		if uci -q get dhcp.@dnsmasq[0] >/dev/null; then
			uci rename dhcp.@dnsmasq[0]='main_dns'
		else
			uci set dhcp.main_dns='dnsmasq'
		fi
	fi

	local prev_lan_ip
	prev_lan_ip="$(uci -q get dhcp.main_dns._sw2_lan_ip)"
	if [ -n "$prev_lan_ip" ] && [ "$prev_lan_ip" != "$lan_ip" ] && [ "$(uci -q get dhcp.main_dns._sw2_add_lan)" = "1" ]; then
		uci -q del_list dhcp.main_dns.listen_address="$prev_lan_ip"
		uci -q delete dhcp.main_dns._sw2_add_lan
	fi

	uci_set_if_diff dhcp main_dns _switch2_managed '1'
	uci_set_if_diff dhcp main_dns _sw2_lan_ip "$lan_ip"

	if uci_add_list_unique dhcp main_dns listen_address "$lan_ip"; then
		uci set dhcp.main_dns._sw2_add_lan='1'
	fi
	if uci_add_list_unique dhcp main_dns listen_address '127.0.0.1'; then
		uci set dhcp.main_dns._sw2_add_lo_ip='1'
	fi
	if uci_add_list_unique dhcp main_dns interface 'loopback'; then
		uci set dhcp.main_dns._sw2_add_lo_if='1'
	fi
	if [ "$(uci -q get dhcp.main_dns.bind_interfaces)" != "1" ]; then
		uci set dhcp.main_dns.bind_interfaces='1'
		uci set dhcp.main_dns._sw2_add_bind='1'
	fi

	if [ -z "$(uci -q get dhcp.lan.instance)" ]; then
		uci set dhcp.lan.instance='main_dns'
		uci set dhcp.lan._switch2_managed='1'
	fi

	if [ "$force_dhcp" = "1" ]; then
		if [ "$(uci -q get dhcp.lan.force)" != "1" ]; then
			uci set dhcp.lan.force='1'
			uci set dhcp.lan._switch2_force_managed='1'
		fi
	else
		if [ "$(uci -q get dhcp.lan._switch2_force_managed)" = "1" ]; then
			uci -q delete dhcp.lan.force
			uci -q delete dhcp.lan._switch2_force_managed
		fi
	fi

	if [ "$(uci -q get dhcp.nintendo_dns)" != "dnsmasq" ]; then
		uci set dhcp.nintendo_dns='dnsmasq'
	fi
	uci_add_list_unique dhcp nintendo_dns notinterface 'lan'
	if [ "$(uci -q get dhcp.nintendo_dns.listen_address)" != "$spoof_ip" ]; then
		uci -q delete dhcp.nintendo_dns.listen_address
		uci add_list dhcp.nintendo_dns.listen_address="$spoof_ip"
	fi
	uci_set_if_diff dhcp nintendo_dns bind_interfaces '1'
	uci_set_if_diff dhcp nintendo_dns port '53'
	uci_set_if_diff dhcp nintendo_dns noresolv '1'
	uci_set_if_diff dhcp nintendo_dns localuse '0'
	uci_set_if_diff dhcp nintendo_dns rebind_protection '0'

	uci -q delete dhcp.nintendo_dns.address
	local added_domain=0
	add_nintendo_domain() {
	    local d="$1"
	    [ -n "$d" ] && uci add_list dhcp.nintendo_dns.address="/${d}/${spoof_ip}" && added_domain=1
	}
	config_list_foreach global test_domain add_nintendo_domain
	if [ "$added_domain" -eq 0 ] && [ -n "$domains" ]; then
	    for d in $domains; do
	        add_nintendo_domain "$d"
	    done
	fi
	
	# 兜底防止列表意外为空
	if [ "$added_domain" -eq 0 ]; then
	    uci add_list dhcp.nintendo_dns.address="/ctest.p01.ctest.srv.nintendo.net/${spoof_ip}"
	fi

	uci_add_list_unique dhcp nintendo_dns server '//'
	uci_set_if_diff dhcp nintendo_dns leasefile '/tmp/dhcp.leases.nintendo'

	if [ "$(uci -q get dhcp.switch2)" != "tag" ]; then
		uci set dhcp.switch2='tag'
	fi
	if [ "$(uci -q get dhcp.switch2.dhcp_option)" != "6,${spoof_ip}" ]; then
		uci -q delete dhcp.switch2.dhcp_option
		uci add_list dhcp.switch2.dhcp_option="6,${spoof_ip}"
	fi

	local guard=0
	while [ $guard -lt 100 ] && uci -q show dhcp | grep -q "dhcp\.@host\[[0-9]*\]\.tag='switch2'"; do
		local idx
		idx=$(uci -q show dhcp | grep "dhcp\.@host\[[0-9]*\]\.tag='switch2'" | head -n1 | sed -E 's/.*@host\[([0-9]+)\].*/\1/')
		if [ -n "$idx" ]; then
			uci -q delete dhcp.@host[$idx] || break
		else
			break
		fi
		guard=$((guard + 1))
	done

	add_host_entry() {
		local cfg="$1"
		local name mac ip
		config_get name "$cfg" name "Switch2"
		config_get mac "$cfg" mac ""
		config_get ip "$cfg" ip ""
		mac=$(echo "$mac" | tr 'a-f' 'A-F' | tr -d ' ')
		[ -z "$mac" ] && return
		local existing_idx
		existing_idx=$(uci -q show dhcp | grep -i "dhcp\.@host\[[0-9]*\]\.mac=.*${mac}" | head -n1 | sed -E 's/.*@host\[([0-9]+)\].*/\1/')
		[ -n "$existing_idx" ] && uci -q delete dhcp.@host[$existing_idx]
		local hsec
		hsec=$(uci add dhcp host)
		uci set dhcp.$hsec.name="$name"
		uci set dhcp.$hsec.dns='1'
		uci set dhcp.$hsec.mac="$mac"
		[ -n "$ip" ] && uci set dhcp.$hsec.ip="$ip"
		uci set dhcp.$hsec.tag='switch2'
	}
	config_foreach add_host_entry device
	uci commit dhcp
}
apply_uhttpd() {
	local lan_ip="$1"
	local spoof_ip="$2"
	ensure_cgi

	if [ "$(uci -q get uhttpd.main._switch2_managed)" != "1" ]; then
		local cur_listen cur_redir
		cur_listen=$(uci -q get uhttpd.main.listen_http)
		if [ -n "$cur_listen" ]; then
			uci -q delete uhttpd.main._sw2_orig_listen
			for item in $cur_listen; do
				uci add_list uhttpd.main._sw2_orig_listen="$item"
			done
		fi
		cur_redir=$(uci -q get uhttpd.main.redirect_https)
		[ -n "$cur_redir" ] && uci set uhttpd.main._sw2_orig_redir="$cur_redir"
		uci set uhttpd.main._switch2_managed='1'
	fi

	uci -q delete uhttpd.main.listen_http
	uci_add_list_unique uhttpd main listen_http "${lan_ip}:80"
	uci_add_list_unique uhttpd main listen_http "127.0.0.1:80"
	uci_set_if_diff uhttpd main redirect_https '0'

	if [ "$(uci -q get uhttpd.nintendo_ctest)" != "uhttpd" ]; then
		uci set uhttpd.nintendo_ctest='uhttpd'
	fi
	if [ "$(uci -q get uhttpd.nintendo_ctest.listen_http)" != "${spoof_ip}:80" ]; then
		uci -q delete uhttpd.nintendo_ctest.listen_http
		uci add_list uhttpd.nintendo_ctest.listen_http="${spoof_ip}:80"
	fi
	uci_set_if_diff uhttpd nintendo_ctest home '/www_nintendo'
	uci_set_if_diff uhttpd nintendo_ctest cgi_prefix '/cgi-bin'
	uci_add_list_unique uhttpd nintendo_ctest index_page 'cgi-bin/ctest'
	uci_set_if_diff uhttpd nintendo_ctest error_page '/cgi-bin/ctest'
	uci_set_if_diff uhttpd nintendo_ctest rfc1918_filter '0'
	uci_set_if_diff uhttpd nintendo_ctest no_dirlists '1'
	uci_set_if_diff uhttpd nintendo_ctest max_requests '3'
	uci_set_if_diff uhttpd nintendo_ctest max_connections '20'
	uci_set_if_diff uhttpd nintendo_ctest script_timeout '10'
	uci_set_if_diff uhttpd nintendo_ctest network_timeout '10'
	uci commit uhttpd
}

ensure_fw_user_include() {
	local is_fw4_flag="$1"
	local has_user_inc=0
	local i=0
	while uci -q get firewall.@include[$i] >/dev/null; do
		if [ "$(uci -q get firewall.@include[$i].path)" = "$FW_USER" ]; then
			has_user_inc=1
			uci_set_if_diff firewall "@include[$i]" enabled '1'
			[ "$is_fw4_flag" = "1" ] && uci_set_if_diff firewall "@include[$i]" fw4_compatible '1'
			break
		fi
		i=$((i + 1))
	done
	if [ "$has_user_inc" -eq 0 ]; then
		uci set firewall.switch2_fw_user='include'
		uci set firewall.switch2_fw_user.type='script'
		uci set firewall.switch2_fw_user.path="$FW_USER"
		[ "$is_fw4_flag" = "1" ] && uci set firewall.switch2_fw_user.fw4_compatible='1'
		uci set firewall.switch2_fw_user.enabled='1'
	fi
	uci commit firewall
}

apply_firewall() {
	local fw_mode="$1"
	cleanup_firewall

	TMP_MACS="/tmp/switch2-block.macs"
	: > "$TMP_MACS"

	collect_macs() {
		local cfg="$1"
		local mac block_wan
		config_get mac "$cfg" mac ""
		config_get block_wan "$cfg" block_wan "1"
		mac=$(echo "$mac" | tr 'a-f' 'A-F' | tr -d ' ')
		[ -z "$mac" ] && return
		[ "$block_wan" != "1" ] && return
		grep -qi "^${mac}$" "$TMP_MACS" || echo "$mac" >> "$TMP_MACS"
	}
	config_foreach collect_macs device

	if [ ! -s "$TMP_MACS" ]; then
		rm -f "$TMP_MACS"
		return 0
	fi

	if is_fw4; then
		if [ "$fw_mode" = "nftables_d" ]; then
			log_msg "Using fw4 + native /etc/nftables.d/ mode"
			mkdir -p /etc/nftables.d
			{
				echo "chain switch2_block_input {"
				echo "	type filter hook input priority filter - 5; policy accept;"
				while read -r mac; do
					echo "	ether saddr $mac ip6 nexthdr icmpv6 counter drop comment \"Block_Switch2_IPv6_Input\""
				done < "$TMP_MACS"
				echo "}"
				echo ""
				echo "chain switch2_block_forward {"
				echo "	type filter hook forward priority filter - 5; policy accept;"
				while read -r mac; do
					echo "	ether saddr $mac counter drop comment \"Block_Switch2_All_Forward\""
				done < "$TMP_MACS"
				echo "}"
			} > "$NFT_D_FILE"
		else
			log_msg "Using fw4 + /etc/firewall.user mode"
			ensure_fw_user_include "1"
			[ ! -f "$FW_USER" ] && touch "$FW_USER"
			{
				echo "# BEGIN SWITCH2-BLOCK"
				while read -r mac; do
					if ! grep -q "ether saddr $mac ip6 nexthdr icmpv6" "$FW_USER"; then
						echo "nft insert rule inet fw4 input ether saddr $mac ip6 nexthdr icmpv6 counter drop comment \"Block_Switch2_IPv6_Input\""
					fi
					if ! grep -q "ether saddr $mac counter drop" "$FW_USER"; then
						echo "nft insert rule inet fw4 forward ether saddr $mac counter drop comment \"Block_Switch2_All_Forward\""
					fi
				done < "$TMP_MACS"
				echo "# END SWITCH2-BLOCK"
			} >> "$FW_USER"
		fi
	else
		log_msg "Using fw3 (iptables/ip6tables) + /etc/firewall.user mode"
		ensure_fw_user_include "0"
		[ ! -f "$FW_USER" ] && touch "$FW_USER"
		{
			echo "# BEGIN SWITCH2-BLOCK"
			while read -r mac; do
				if ! grep -q -- "--mac-source $mac -p ipv6-icmp" "$FW_USER"; then
					echo "command -v ip6tables >/dev/null 2>&1 && ip6tables -I INPUT -m mac --mac-source $mac -p ipv6-icmp -m comment --comment \"Block_Switch2_IPv6_Input\" -j DROP"
				fi
				if ! grep -q -- "--mac-source $mac -m comment --comment \"Block_Switch2_All_Forward\"" "$FW_USER"; then
					echo "command -v ip6tables >/dev/null 2>&1 && ip6tables -I FORWARD -m mac --mac-source $mac -m comment --comment \"Block_Switch2_All_Forward\" -j DROP"
					echo "command -v iptables >/dev/null 2>&1 && iptables -I FORWARD -m mac --mac-source $mac -m comment --comment \"Block_Switch2_All_Forward\" -j DROP"
				fi
			done < "$TMP_MACS"
			echo "# END SWITCH2-BLOCK"
		} >> "$FW_USER"
	fi
	rm -f "$TMP_MACS"
}

reload_proxy_fw() {
	[ -x /usr/share/shadowsocksr/firewall.include ] && /usr/share/shadowsocksr/firewall.include >/dev/null 2>&1
	[ -x /usr/share/passwall/firewall.include ] && /usr/share/passwall/firewall.include >/dev/null 2>&1
	[ -x /usr/share/passwall2/firewall.include ] && /usr/share/passwall2/firewall.include >/dev/null 2>&1
}

start_service() {
	config_load "$CONF"
	local enabled lan_ip spoof_ip test_domain force_dhcp fw_mode
	config_get_bool enabled global enabled 0
	config_get_bool force_dhcp global force_dhcp 0
	config_get fw_mode global fw_mode "firewall_user"
	config_get lan_ip global lan_ip ""
	config_get spoof_ip global spoof_ip ""
	config_get test_domain global test_domain "ctest.p01.ctest.srv.nintendo.net"

	if [ "$enabled" -eq 0 ]; then
		stop_service
		return 0
	fi

	# 若未配置 IP，自动动态探测并回写 UCI，绝不使用硬编码 IP
	if [ -z "$lan_ip" ]; then
		lan_ip=$(detect_lan_ip)
		[ -n "$lan_ip" ] && uci_set_if_diff "$CONF" global lan_ip "$lan_ip"
	fi
	if [ -z "$spoof_ip" ] && [ -n "$lan_ip" ]; then
		spoof_ip=$(derive_spoof_ip "$lan_ip")
		[ -n "$spoof_ip" ] && uci_set_if_diff "$CONF" global spoof_ip "$spoof_ip"
	fi
	uci commit "$CONF"

	if [ -z "$lan_ip" ] || [ -z "$spoof_ip" ] || [ "$lan_ip" = "$spoof_ip" ]; then
		log_msg "Error: Invalid or undetected LAN/Spoof IP (LAN: '$lan_ip', Spoof: '$spoof_ip'), aborting."
		return 1
	fi

	log_msg "Applying Switch 2 spoof & block (LAN: $lan_ip, Spoof: $spoof_ip, ForceDHCP: $force_dhcp, FWMode: $fw_mode)"
	apply_network "$spoof_ip"
	apply_dhcp "$lan_ip" "$spoof_ip" "$test_domain" "$force_dhcp"
	apply_uhttpd "$lan_ip" "$spoof_ip"
	apply_firewall "$fw_mode"

	# 仅当 nintendo 接口尚未激活时才手动 ifup，避免与 netifd 自动重载冲突导致两次 up/down
	if ! ifstatus nintendo 2>/dev/null | grep -q '"up": true'; then
		ifup nintendo >/dev/null 2>&1
	fi
	sleep 1
	/etc/init.d/dnsmasq restart
	/etc/init.d/uhttpd restart
	/etc/init.d/firewall restart
	
	# 兜底检测：若选择了 nftables_d 模式，但固件未自动 include /etc/nftables.d/，则手动注入 table inet fw4
	if is_fw4 && [ "$fw_mode" = "nftables_d" ] && [ -s "$NFT_D_FILE" ]; then
		if ! nft list table inet fw4 2>/dev/null | grep -q "switch2_block_forward"; then
			log_msg "fw4 did not auto-include $NFT_D_FILE, injecting manually into inet fw4"
			{
				echo "table inet fw4 {"
				cat "$NFT_D_FILE"
				echo "}"
			} | nft -f - 2>/dev/null
		fi
	fi
	
	reload_proxy_fw
}

stop_service() {
	config_load "$CONF"
	local lan_ip
	config_get lan_ip global lan_ip ""
	[ -z "$lan_ip" ] && lan_ip=$(detect_lan_ip)

	log_msg "Disabling Switch 2 spoof & restoring default OpenWrt services"
	cleanup_firewall
	cleanup_uhttpd
	cleanup_dhcp "$lan_ip"
	ifdown nintendo >/dev/null 2>&1
	cleanup_network
	
	/etc/init.d/dnsmasq restart
	/etc/init.d/uhttpd restart
	/etc/init.d/firewall restart
	reload_proxy_fw
}

reload_nft_only() {
	config_load "$CONF"
	local enabled fw_mode
	config_get_bool enabled global enabled 0
	config_get fw_mode global fw_mode "firewall_user"
	if [ "$enabled" -eq 1 ]; then
		apply_firewall "$fw_mode"
		/etc/init.d/firewall restart
		if is_fw4 && [ "$fw_mode" = "nftables_d" ] && [ -s "$NFT_D_FILE" ]; then
			if ! nft list table inet fw4 2>/dev/null | grep -q "switch2_block_forward"; then
				{
					echo "table inet fw4 {"
					cat "$NFT_D_FILE"
					echo "}"
				} | nft -f - 2>/dev/null
			fi
		fi
		reload_proxy_fw
	fi
}

case "$1" in
	start|restart)
		start_service
		;;
	stop)
		stop_service
		;;
	nft_only)
		reload_nft_only
		;;
	*)
		echo "Usage: $0 {start|stop|restart|nft_only}"
		exit 1
		;;
esac
