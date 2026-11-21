{
	"luci-app-switch2-block": {
		"description": "Grant UCI and diagnostic access for Switch 2 Connection Spoof",
		"read": {
			"uci": [ "switch2-block" ],
			"ubus": {
				"file": [ "exec", "stat", "read" ]
			},
			"file": {
				"/usr/libexec/switch2-block/test.sh": [ "exec" ],
				"/etc/nftables.d/99-switch2-block.nft": [ "read" ],
				"/etc/firewall.user": [ "read" ],
				"/sbin/fw4": [ "stat" ],
				"/usr/sbin/fw4": [ "stat" ]
			}
		},
		"write": {
			"uci": [ "switch2-block" ]
		}
	}
}
