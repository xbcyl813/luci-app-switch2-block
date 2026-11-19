# luci-app-switch2-block
**简体中文** | [English](./README_EN.md)

通过独立 dnsmasq 实例与 uHTTPd 伪装响应，使 Switch 2 / Switch 1 在完全断绝外网更新的情况下通过局域网连接测试。同时通过自动生成的防火墙规则，禁止Switch2连接外网，避免主机意外升级或被supernag的风险。

一、插件特性：
1、本插件为OpenWRT软路由插件，通过独立 dnsmasq 实例与 uHTTPd 伪装响应，使 Switch 2  在完全断绝外网更新的情况下通过局域网连接测试。
💡**而且启用本插件并不会影响网络中其他终端正常上网以及流量代理。**

2、插件兼容19.XX-25.XX各版本OpenWRT固件，默认编译为ipk格式，如果需要apk格式，请自行编译。（因为我自己用的LEDE固件使用的插件是ipk格式，所以未编译apk格式，请见谅。）

3、插件兼容fw3和fw4防火墙，且可以自动匹配当前防火墙版本，提供拦截Switch2拦截外网的防火墙规则。

4、插件自带拦截规则和伪装结果检测功能，可以直接在插件中查看伪装检测结果。

二、插件截图

<img width="2174" height="1786" alt="01 主界面" src="https://github.com/user-attachments/assets/b96c7a1c-a422-486f-b83d-4c8869d0689a" />

<img width="815" height="290" alt="02 Switch2设置" src="https://github.com/user-attachments/assets/3c353fcc-dd3d-4770-b090-576829f5dd84" />

<img width="550" height="360" alt="03 插件自检" src="https://github.com/user-attachments/assets/a3759b9c-4c91-4ec1-89b9-329930495a56" />

三、注意事项

 1、插件会修改的配置文件包括：/etc/config/文件夹下的 dhcp、network、uhttpd 3个配置文件（使用插件前，请将这3个配置文件自行备份），并在同目录下生成插件配置文件 switch2-block。

2、防火墙规则存放的位置： （1）fw4防火墙，如果“规则写入方式”选择的是“ 写入/etc/nftables.d/规则原生规则目录”，则会保存在 /etc/nftables.d/99-switch2-block.nft 文件里，在防火墙启动时自动写入规则列表。普通固件请使用这种方式。 （2）fw4防火墙，如果规则写入方式选择的是“ 写入/etc/firewall.user 自定义规则文件”，则会把防火墙规则写入/etc/firewall.user 文件。 注意，该种方式只有大雕的Lede固件和其他少数允许使用firewall.user添加自定义防火墙规则的固件才能使用。 （3）fw3防火墙，将防火墙规则写入/etc/firewall.user 文件。

3、必须在插件中准确设置Switch2的mac地址，只有mac地址正确，才能有效防止Switch2主机访问外网。否则防火墙规则会失效，造成主机联到外网。Switch2主机的mac地址可以直接在主机设置的“互联网”功能中查看。 如果连接了wifi或者未联网状态，这里默认查看的是主机无线网卡的mac地址，如果连接了底座，这里看到的就是底座以太网卡的mac地址。 一定要注意区分！！

4、如果路由器启用了 SSR Plus+ / PassWall / OpenClash 等代理插件，请务必将插件中设置的「任天堂联网测试域名」及「Switch 专用伪装辅助 IP」加入不走代理的白名单，防止流量被代理插件劫持。例如，截图中就是 ctest.p01.ctest.srv.nintendo.net 和 192.168.10.254。

5、由于OpenWRT固件版本众多，兼容性不一，插件不能保证能在所有插件上都能正常工作。因此，为保证不会因为插件工作不正常而造成Switch2主机意外升级，请一定在初次使用插件前，断开路由器的互联网连接！在配置好插件后，首先点击“立即测试伪装服务”按钮，进行插件设置是否生效的检查。只有自建结果3项都返回成功的结果，尤其是防火墙规则状态正常，才能恢复路由器的互联网连接。切记切记!!
     需重点检查确认的结果：
   （1）DNS劫持状态检查：域名下方解析出的ip地址必须是你之前设置的伪装辅助ip。如果不是，那就是dns解析被重定向了，产生了dns泄露。请检查路由器是否启用了SSR Plus+ / PassWall / OpenClash 等代理插件，如果是，请按第4点注意事项处理。
   （2）80端口占用检查：需要确认uHTTPd的80端口未被占用，否则switch2无法正常获得伪装的联网验证结果。如果检查结果提示80端口被占用，请自行检查具体被哪个插件占用，并解决占用冲突。
   （3）防火墙规则检查：如果检查结果提示防火墙规则未生效，或未查询到任何防火墙规则，请不要将Switch2连接到网络。一定要在确保防火墙规则生效的状态下，再连接Switch2。

6、插件正常生效后，可以连接路由器所在wifi，让Switch2自动获取ip和DNS服务器。Switch2获取的DNS服务器地址即插件中设置的Switch 专用伪装辅助 IP，如果在插件中为Switch2指定了静态地址，则Switch2会固定使用这个ip。如果插件设置时没有为Switch2分配静态ip，则由路由器自动分配。也可以在Switch2的连接设置里手动指定ip、DNS，设置值与插件一致就可以正常工作。

7、插件安装后，可以通过“网络”菜单下的“Switch 2 联网伪装”菜单项访问插件。
  也可以直接通过  http://路由器ip/cgi-bin/luci/admin/network/switch2-block  地址访打开插件页面。
  如果菜单没有刷新出来，可以ssh到软路由后台，执行如下命令刷新菜单。重启软路由也可以刷新菜单。
  
        rm -rf /tmp/luci-indexcache /tmp/luci-modulecache/
        /etc/init.d/rpcd restart
        /etc/init.d/uhttpd restart      
 
 8、可以通过查看系统日志中插件的启动日志判断插件是否工作正常。正常工作的插件启动日志如下，可以参考对比：
 
      [2026年11月17日 GMT+8 23:43:38] user.notice: switch2-block: Applying Switch 2 spoof & block (LAN: 192.168.10.1, Spoof: 192.168.10.254, ForceDHCP: 0, FWMode: firewall_user)
      [2026年11月17日 GMT+8 23:43:38] user.notice: switch2-block: Using fw4 + /etc/firewall.user mode
      [2026年11月17日 GMT+8 23:43:38] daemon.notice: netifd: Interface 'nintendo' is setting up now
      [2026年11月17日 GMT+8 23:43:38] daemon.notice: netifd: Interface 'nintendo' is now up
      [2026年11月17日 GMT+8 23:43:39] user.notice: firewall: Reloading firewall due to ifup of nintendo (br-lan)
      [2026年11月17日 GMT+8 23:43:39] user.notice: nlbwmon: Reloading nlbwmon due to ifup of nintendo (br-lan)

