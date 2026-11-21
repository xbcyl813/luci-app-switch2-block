include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-switch2-block
PKG_VERSION:=1.0.2
PKG_RELEASE:=1

LUCI_TITLE:=LuCI support for Nintendo Switch 2 Connection Spoof & Update Blocker
LUCI_DEPENDS:=+luci-base +uhttpd +curl
LUCI_PKGARCH:=all

define Package/$(PKG_NAME)/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	rm -rf /tmp/luci-indexcache /tmp/luci-modulecache/
	/etc/init.d/rpcd reload >/dev/null 2>&1
fi
exit 0
endef

define Package/$(PKG_NAME)/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/switch2-block stop >/dev/null 2>&1
	/etc/init.d/switch2-block disable >/dev/null 2>&1
fi
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
