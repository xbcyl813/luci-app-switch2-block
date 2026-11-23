#!/bin/sh

SPOOF_IP="$1"
shift
FIRST_DOMAIN="$1"
[ -z "$FIRST_DOMAIN" ] && FIRST_DOMAIN="ctest.p01.ctest.srv.nintendo.net"

echo "=== DNS_RESULT ==="
first_dns=1
for domain in "$@"; do
	[ -z "$domain" ] && continue
	out=$(nslookup "$domain" "$SPOOF_IP" 2>&1 | grep -viE "can't find.*(REFUSED|No answer)" | sed '/^[[:space:]]*$/d')
	if [ "$first_dns" -eq 1 ]; then
		echo "$out" | sed 's/^Name:/\nName:/'
		first_dns=0
	else
		echo ""
		if echo "$out" | grep -q "^Name:"; then
			echo "$out" | awk '/^Name:/{found=1} found{print}'
		else
			echo "$out"
		fi
	fi
done

echo ""
echo "=== DNS_AAAA_CHECK ==="
ipv6_blocked=1
for domain in "$@"; do
	[ -z "$domain" ] && continue
	# 兼容 BusyBox nslookup 与完整版 nslookup 的 AAAA 查询语法
	aaaa_out=$(nslookup -type=AAAA "$domain" "$SPOOF_IP" 2>&1 || nslookup -q=AAAA "$domain" "$SPOOF_IP" 2>&1)
	# 若应答中出现合法 IPv6 地址（含冒号且非 Server 行），说明未屏蔽 IPv6 解析
	if echo "$aaaa_out" | awk 'BEGIN{after_server=0} /^Server:/{next} /^Address/{after_server=1; next} after_server && /:/ && !/can'\''t find/ && !/NXDOMAIN/ && !/SERVFAIL/{found=1} END{exit (found ? 0 : 1)}'; then
		ipv6_blocked=0
		break
	fi
done
if [ "$(uci -q get dhcp.nintendo_dns.filter_aaaa)" = "1" ] && [ "$ipv6_blocked" -eq 1 ]; then
	echo "IPV6_BLOCKED=1"
elif [ "$ipv6_blocked" -eq 1 ]; then
	echo "IPV6_BLOCKED=1"
else
	echo "IPV6_BLOCKED=0"
fi

TMP_RESP="/tmp/switch2_ctest_resp.$$"
curl -s -i --noproxy '*' --connect-timeout 3 -m 5 -H "Host: $FIRST_DOMAIN" "http://$SPOOF_IP" 2>&1 | tr -d '\r' > "$TMP_RESP"

echo "=== HTTP_HEADER ==="
awk 'BEGIN{hdr=1} /^$/{hdr=0; exit} hdr{print}' "$TMP_RESP"

RAW_HDR_LEN=$(awk 'BEGIN{n=0} {n += length($0) + 1; if ($0 == "") {print n; exit}}' "$TMP_RESP")
TOTAL_LEN=$(wc -c < "$TMP_RESP" 2>/dev/null | tr -d ' ')
if [ -n "$RAW_HDR_LEN" ] && [ -n "$TOTAL_LEN" ] && [ "$TOTAL_LEN" -ge "$RAW_HDR_LEN" ]; then
	BODY_LEN=$((TOTAL_LEN - RAW_HDR_LEN))
else
	BODY_LEN=0
fi

echo "=== HTTP_BODY_LEN ==="
printf "%s\n" "$BODY_LEN"

echo "=== HTTP_BODY ==="
awk 'body{print} /^$/{body=1}' "$TMP_RESP"
rm -f "$TMP_RESP"

echo "=== HTTP_PORT_OWNER ==="
if command -v ss >/dev/null 2>&1; then
	ss -tulnp 2>/dev/null | grep -E "(0\.0\.0\.0:80|${SPOOF_IP}:80|\*:80)"
else
	netstat -tulnp 2>/dev/null | grep -E "(0\.0\.0\.0:80|${SPOOF_IP}:80)"
fi

echo ""
echo "=== FW_ACTIVE_RULES ==="
if [ -x /sbin/fw4 ] || command -v fw4 >/dev/null 2>&1; then
	nft list ruleset 2>/dev/null | grep "Block_Switch2_" | sed 's/^[ \t]*//'
else
	{
		iptables -S FORWARD 2>/dev/null | grep "Block_Switch2_"
		ip6tables -S INPUT 2>/dev/null | grep "Block_Switch2_"
		ip6tables -S FORWARD 2>/dev/null | grep "Block_Switch2_"
	}
fi
