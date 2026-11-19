#!/bin/sh

SPOOF_IP="$1"
shift

echo "=== DNS_RESULT ==="
first_dns=1
for domain in "$@"; do
	[ -z "$domain" ] && continue
	out=$(nslookup "$domain" "$SPOOF_IP" 2>&1 | grep -v "can't find.*REFUSED" | sed '/^[[:space:]]*$/d')
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
