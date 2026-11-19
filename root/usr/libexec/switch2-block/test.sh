#!/bin/sh

SPOOF_IP="$1"
shift
DOMAINS="$*"

[ -z "$SPOOF_IP" ] && SPOOF_IP=$(uci -q get switch2-block.global.spoof_ip)
[ -z "$DOMAINS" ] && DOMAINS=$(uci -q get switch2-block.global.test_domain)
[ -z "$DOMAINS" ] && DOMAINS="ctest.p01.ctest.srv.nintendo.net"

FIRST_DOMAIN=$(echo "$DOMAINS" | awk '{print $1}')

echo "=== DNS_RESULT ==="
for d in $DOMAINS; do
	nslookup -type=A "$d" "$SPOOF_IP" 2>&1
done

echo "=== HTTP_HEADER ==="
curl -s -i --noproxy '*' --connect-timeout 3 -m 5 -H "Host: $FIRST_DOMAIN" "http://$SPOOF_IP" 2>&1 | tr -d '\r' | sed '/^$/q'

echo "=== HTTP_BODY_LEN ==="
curl -s --noproxy '*' --connect-timeout 3 -m 5 -H "Host: $FIRST_DOMAIN" "http://$SPOOF_IP" 2>/dev/null | wc -c | tr -d ' \n'

echo ""
echo "=== HTTP_BODY ==="
curl -s --noproxy '*' --connect-timeout 3 -m 5 -H "Host: $FIRST_DOMAIN" "http://$SPOOF_IP" 2>/dev/null

echo ""
echo "=== HTTP_PORT_OWNER ==="
if command -v ss >/dev/null 2>&1; then
	ss -tulnp 2>/dev/null | grep -E "(0\.0\.0\.0:80|${SPOOF_IP}:80|\*:80)"
else
	netstat -tulnp 2>/dev/null | grep -E "(0\.0\.0\.0:80|${SPOOF_IP}:80)"
fi

echo ""
echo "=== FW_ACTIVE_RULES ==="
if [ -x /sbin/fw4 ] || command -v fw4 >/dev/null 2>&1 || command -v nft >/dev/null 2>&1; then
	nft list ruleset 2>/dev/null | grep "Block_Switch2_" | sed 's/^[ \t]*//'
else
	{
		iptables -S FORWARD 2>/dev/null | grep "Block_Switch2_"
		ip6tables -S INPUT 2>/dev/null | grep "Block_Switch2_"
		ip6tables -S FORWARD 2>/dev/null | grep "Block_Switch2_"
	}
fi
