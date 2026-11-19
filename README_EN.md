# luci-app-switch2-block

**English** | [简体中文](./README.md)

Allows Switch 2 / Switch 1 to pass the local network connection test while completely blocking external internet updates via a standalone `dnsmasq` instance and spoofed `uHTTPd` responses. At the same time, it automatically generates firewall rules to prevent the Switch 2 from accessing the internet, eliminating the risk of accidental system updates or triggering a "supernag".

## I. Features:
1. This is an OpenWRT soft-router plugin that uses a standalone `dnsmasq` instance and spoofed `uHTTPd` responses to let the Switch 2 pass the LAN connection test while completely isolated from external updates.  
  💡 **Enabling this plugin will not affect normal internet access or proxy traffic for other devices on your network.**

2. Compatible with OpenWRT firmware versions 19.XX through 25.XX. Compiled in `.ipk` format by default. If you need the `.apk` format, please compile it yourself. *(Apologies for not providing `.apk` builds, as my own LEDE firmware uses `.ipk` packages.)*

3. Compatible with both `fw3` and `fw4` firewalls. It automatically detects your current firewall version and generates rules to block the Switch 2 from accessing the external internet.

4. Includes built-in self-check features to verify the blocking rules and spoofing results directly within the plugin interface.

## II. Screenshots

<img width="2174" height="1786" alt="01 Main Interface" src="https://github.com/user-attachments/assets/d02f63b0-b3bf-45ac-9c71-a616efbb03eb" />

<img width="815" height="290" alt="02 Switch2 Settings" src="https://github.com/user-attachments/assets/c483d9ef-bb61-4f4b-a510-7ac9f33f5409" />

<img width="550" height="360" alt="03 Plugin Self-Check" src="https://github.com/user-attachments/assets/e763ff7a-73c6-4f99-b94e-189d871a3a00" />

## III. Important Notes

1. **Modified Configuration Files**: The plugin modifies three configuration files under `/etc/config/`: `dhcp`, `network`, and `uhttpd` **(please back up these three files before using the plugin)**. It will also generate a plugin configuration file named `switch2-block` in the same directory.

2. **Firewall Rule Locations**:
   - **(1) `fw4` Firewall (Native Directory)**: If "Rule Writing Method" is set to *"Write to `/etc/nftables.d/` native rule directory"*, rules are saved in `/etc/nftables.d/99-switch2-block.nft` and automatically loaded when the firewall starts. **Use this option for standard OpenWRT firmware.**
   - **(2) `fw4` Firewall (Custom File)**: If "Rule Writing Method" is set to *"Write to `/etc/firewall.user` custom rule file"*, rules are appended to `/etc/firewall.user`. **Note:** This option only works on Lean's LEDE firmware and a few other custom builds that support custom rules via `firewall.user`.
   - **(3) `fw3` Firewall**: Firewall rules are written directly to `/etc/firewall.user`.

3. **MAC Address Accuracy**: You must enter the exact MAC address of your Switch 2 in the plugin. The firewall rules will only block internet access if the MAC address is accurate; otherwise, the rules will fail and the console will connect to the internet. You can find the MAC address under **System Settings -> Internet** on your console. When connected via Wi-Fi or offline, this displays the **wireless MAC address**; when docked with a wired connection, it displays the **dock's Ethernet MAC address**. **Be sure to distinguish between the two!**

4. **Proxy Plugin Whitelisting**: If your router runs proxy plugins such as **SSR Plus+**, **PassWall**, or **OpenClash**, you must add both the **"Nintendo Connection Test Domain"** and the **"Switch Dedicated Spoofing Auxiliary IP"** configured in this plugin to your proxy bypass/whitelist to prevent traffic hijacking. For example, as shown in the screenshots, whitelist `ctest.p01.ctest.srv.nintendo.net` and `192.168.10.254`.

5. **Disconnect Internet Before First-Time Setup**: Due to the wide variety of OpenWRT firmware versions and differing compatibility, this plugin is not guaranteed to work on every build. To prevent your Switch 2 from accidentally updating if the plugin malfunctions, **disconnect your router from the internet before using the plugin for the first time!** After configuring the plugin, click the **"Test Spoofing Service Now"** button to verify that the settings are active. Only reconnect your router to the internet after all 3 self-check items return a successful status—especially confirming that the firewall blocking rules are active. **Please remember this!!**

   **Key Self-Check Items to Verify**:
   - **(1) DNS Hijacking Status Check**: The resolved IP address shown below the domain name must match the spoofing auxiliary IP you configured earlier. If it does not, your DNS queries are being redirected, resulting in a DNS leak. Please check if proxy plugins like **SSR Plus+**, **PassWall**, or **OpenClash** are enabled on your router, and follow Note #4 if they are.
   - **(2) Port 80 Occupancy Check**: Confirm that port 80 for `uHTTPd` is not occupied by another service; otherwise, the Switch 2 will not receive the spoofed connection verification response. If the check indicates that port 80 is occupied, identify which plugin or service is using it and resolve the port conflict.
   - **(3) Firewall Rule Check**: If the check indicates that the firewall rules are not active or no rules are found, **do not connect your Switch 2 to the network**. Make sure the firewall blocking rules are confirmed active before connecting your console.

6. **Connecting Your Switch 2**: Once the plugin is confirmed working, connect your Switch 2 to the router's Wi-Fi and set it to obtain the IP address and DNS server automatically. The Switch 2 will automatically receive the **"Switch Dedicated Spoofing Auxiliary IP"** configured in the plugin as its DNS server. If you assigned a static IP to the Switch 2 in the plugin, it will always use that IP; if left blank, the router will assign one dynamically via DHCP. Alternatively, you can manually enter the IP and DNS settings on your Switch 2 to match the plugin's configuration, and it will work normally as well.

7. **Accessing the Plugin & Refreshing the Menu**: After installation, you can access the plugin via **Network -> Switch 2 Network Spoofing** in the LuCI menu, or navigate directly to `http://<router-ip>/cgi-bin/luci/admin/network/switch2-block`.  
   If the menu item does not appear immediately, SSH into your router and run the following commands to clear the LuCI cache and refresh the menu (or simply reboot the router):

   ```bash
   rm -rf /tmp/luci-indexcache /tmp/luci-modulecache/
   /etc/init.d/rpcd restart
   /etc/init.d/uhttpd restart
   ```

8. **Checking System Logs**: You can verify whether the plugin is running properly by checking the startup entries in the System Log. Normal startup logs should look similar to the following:

   ```text
   [2026年11月17日 GMT+8 23:43:38] user.notice: switch2-block: Applying Switch 2 spoof & block (LAN: 192.168.10.1, Spoof: 192.168.10.254, ForceDHCP: 0, FWMode: firewall_user)
   [2026年11月17日 GMT+8 23:43:38] user.notice: switch2-block: Using fw4 + /etc/firewall.user mode
   [2026年11月17日 GMT+8 23:43:38] daemon.notice: netifd: Interface 'nintendo' is setting up now
   [2026年11月17日 GMT+8 23:43:38] daemon.notice: netifd: Interface 'nintendo' is now up
   ```
