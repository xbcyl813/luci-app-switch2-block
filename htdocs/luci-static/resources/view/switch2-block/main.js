'use strict';
'require view';
'require form';
'require uci';
'require fs';
'require ui';

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('switch2-block'),
			uci.load('network').catch(function() { return null; }),
			fs.stat('/sbin/fw4').then(function() { return true; }).catch(function() {
				return fs.stat('/usr/sbin/fw4').then(function() { return true; }).catch(function() { return false; });
			})
		]);
	},

	detectNetworkDefaults: function() {
		var rawIp = uci.get('network', 'lan', 'ipaddr') || '';
		if (Array.isArray(rawIp)) {
			rawIp = rawIp[0] || '';
		}
		var detectedLanIp = String(rawIp).trim().split(' ')[0].split('/')[0];
		var detectedSpoofIp = '';
		var prefix = '';

		if (detectedLanIp && detectedLanIp.split('.').length === 4) {
			var parts = detectedLanIp.split('.');
			prefix = parts.slice(0, 3).join('.');
			detectedSpoofIp = (parts[3] === '254') ? (prefix + '.253') : (prefix + '.254');
		}

		return {
			lanIp: detectedLanIp,
			spoofIp: detectedSpoofIp,
			prefix: prefix
		};
	},

	handleTestSpoof: function(m, enableOpt, forceDhcpOpt, lanOpt, spoofOpt, domainOpt, fwModeOpt, isFw4, netDefaults) {
		var savedEnabled = uci.get('switch2-block', 'global', 'enabled') || '0';
		var savedForceDhcp = uci.get('switch2-block', 'global', 'force_dhcp') || '0';
		var savedLanIp = uci.get('switch2-block', 'global', 'lan_ip') || netDefaults.lanIp || '';
		var savedSpoofIp = uci.get('switch2-block', 'global', 'spoof_ip') || netDefaults.spoofIp || '';
		var savedFwMode = uci.get('switch2-block', 'global', 'fw_mode') || 'firewall_user';

		var rawSavedDomains = uci.get('switch2-block', 'global', 'test_domain');
		var savedDomains = Array.isArray(rawSavedDomains)
			? rawSavedDomains
			: (rawSavedDomains ? [rawSavedDomains] : ['ctest.p01.ctest.srv.nintendo.net']);

		var curEnabled = enableOpt ? enableOpt.formvalue('global') : savedEnabled;
		var curForceDhcp = forceDhcpOpt ? forceDhcpOpt.formvalue('global') : savedForceDhcp;
		var curLanIp = lanOpt ? (lanOpt.formvalue('global') || savedLanIp) : savedLanIp;
		var curSpoofIp = spoofOpt ? (spoofOpt.formvalue('global') || savedSpoofIp) : savedSpoofIp;
		var curFwMode = fwModeOpt ? (fwModeOpt.formvalue('global') || savedFwMode) : savedFwMode;

		var rawCurDomains = domainOpt ? domainOpt.formvalue('global') : savedDomains;
		if (!Array.isArray(rawCurDomains)) {
			rawCurDomains = rawCurDomains ? [rawCurDomains] : [];
		}
		var curDomains = [];
		for (var i = 0; i < rawCurDomains.length; i++) {
			var d = String(rawCurDomains[i] || '').trim();
			if (d !== '') {
				curDomains.push(d);
			}
		}

		if (curEnabled !== '1') {
			ui.addNotification(null, E('p', _('Spoof & Blocker is currently disabled. Please enable it and click Save & Apply first.')), 'warning');
			return;
		}

		var pendingChanges = uci.changes();
		var hasPendingUci = pendingChanges && pendingChanges['switch2-block'] && pendingChanges['switch2-block'].length > 0;

		if (hasPendingUci ||
			curEnabled !== savedEnabled ||
			curForceDhcp !== savedForceDhcp ||
			curLanIp !== savedLanIp ||
			curSpoofIp !== savedSpoofIp ||
			JSON.stringify(curDomains) !== JSON.stringify(savedDomains) ||
			curFwMode !== savedFwMode) {
			ui.addNotification(null, E('p', _('Unsaved changes detected on this page or device list. Please click Save & Apply before running self-test!')), 'warning');
			return;
		}

		if (!curSpoofIp) {
			ui.addNotification(null, E('p', _('Spoof Helper IP is empty. Please enter an IP and click Save & Apply.')), 'error');
			return;
		}

		if (curDomains.length === 0) {
			curDomains = ['ctest.p01.ctest.srv.nintendo.net'];
		}

		var devices = uci.sections('switch2-block', 'device') || [];
		var hasBlockDevice = false;
		for (var idx = 0; idx < devices.length; idx++) {
			var dev = devices[idx];
			if (dev.mac && (dev.block_wan === '1' || dev.block_wan === undefined)) {
				hasBlockDevice = true;
				break;
			}
		}

		ui.showModal(_('Running Connectivity Self-Test...'), [
			E('p', { 'class': 'spinning' }, _('Calling test.sh to verify DNS hijacking, uHTTPd 2-byte response, port 80 usage, and firewall rules...'))
		]);
		var targetFwFile = (isFw4 && curFwMode === 'nftables_d')
			? '/etc/nftables.d/99-switch2-block.nft'
			: '/etc/firewall.user';

		var checkFwRule = fs.read(targetFwFile).then(function(content) {
			return (content || '').indexOf('Block_Switch2_') !== -1;
		}).catch(function() {
			return false;
		});

		return Promise.all([
			fs.exec('/usr/libexec/switch2-block/test.sh', [curSpoofIp].concat(curDomains)),
			checkFwRule
		]).then(function(results) {
			var res = results[0];
			var fwRuleInFile = results[1];
			var rawOut = (res.stdout || '') + (res.stderr || '');
			var dnsOut = '', httpHeader = '', bodyLen = '0', body = '', portOwner = '', fwActiveRules = '';

			var mDns = rawOut.match(new RegExp('=== DNS_RESULT ===\\n([\\s\\S]*?)\\n=== HTTP_HEADER ==='));
			var mHdr = rawOut.match(new RegExp('=== HTTP_HEADER ===\\n([\\s\\S]*?)\\n=== HTTP_BODY_LEN ==='));
			var mLen = rawOut.match(new RegExp('=== HTTP_BODY_LEN ===\\n([\\s\\S]*?)\\n=== HTTP_BODY ==='));
			var mBody = rawOut.match(new RegExp('=== HTTP_BODY ===\\n([\\s\\S]*?)\\n=== HTTP_PORT_OWNER ==='));
			var mPort = rawOut.match(new RegExp('=== HTTP_PORT_OWNER ===\\n([\\s\\S]*?)\\n=== FW_ACTIVE_RULES ==='));
			var mFw = rawOut.match(new RegExp('=== FW_ACTIVE_RULES ===\\n([\\s\\S]*)$'));

			if (mDns && mDns[1]) dnsOut = mDns[1].trim();
			if (mHdr && mHdr[1]) httpHeader = mHdr[1].trim();
			if (mLen && mLen[1]) bodyLen = mLen[1].trim();
			if (mBody && mBody[1]) body = mBody[1];
			if (mPort && mPort[1]) portOwner = mPort[1].trim();
			if (mFw && mFw[1]) fwActiveRules = mFw[1].trim();

			var fwRuleLines = [];
			if (fwActiveRules) {
				var rawLines = fwActiveRules.split('\n');
				for (var j = 0; j < rawLines.length; j++) {
					if (rawLines[j].trim() !== '') {
						fwRuleLines.push(rawLines[j]);
					}
				}
			}
			var fwActiveCount = fwRuleLines.length;

			var answerParts = dnsOut.split('Name:').slice(1);
			var dnsOk = (answerParts.length >= curDomains.length);
			if (dnsOk) {
				for (var k = 0; k < answerParts.length; k++) {
					if (answerParts[k].indexOf(curSpoofIp) === -1) {
						dnsOk = false;
						break;
					}
				}
			}

			var httpOk = httpHeader.indexOf('200 OK') !== -1 && body === 'ok' && bodyLen === '2';

			var portStatusColor, portStatusText;
			if (!portOwner) {
				portStatusColor = '#d9534f';
				portStatusText = _('Abnormal: No listener detected on %s:80 (uHTTPd helper instance not running)').format(curSpoofIp);
			} else if (portOwner.indexOf('uhttpd') !== -1 && portOwner.indexOf('nginx') === -1) {
				portStatusColor = 'green';
				portStatusText = _('Normal (Exclusively bound by uHTTPd on %s:80, no port conflict)').format(curSpoofIp);
			} else {
				var procName = _('Other Web Service');
				var pStart = portOwner.indexOf('(("');
				if (pStart !== -1) {
					var pEnd = portOwner.indexOf('"', pStart + 3);
					if (pEnd !== -1) {
						procName = portOwner.substring(pStart + 3, pEnd);
					}
				}
				portStatusColor = '#d9534f';
				portStatusText = _('Conflict: Port 80 is globally occupied by "%s"! Please bind it only to Main LAN IP (%s:80)').format(procName, curLanIp);
			}

			var fwStatusColor, fwStatusText;
			if (!hasBlockDevice) {
				fwStatusColor = 'green';
				fwStatusText = _('Skipped (No device enabled for WAN blocking)');
			} else if (fwRuleInFile && fwActiveCount > 0) {
				fwStatusColor = 'green';
				fwStatusText = _('Written to %s and active in kernel firewall (%d rules)').format(targetFwFile, fwActiveCount);
			} else if (fwRuleInFile && fwActiveCount === 0) {
				fwStatusColor = '#d9534f';
				if (isFw4 && curFwMode === 'nftables_d') {
					fwStatusText = _('Written to %s, but not loaded by kernel! Please switch "fw4 Firewall Rule Mode" to "/etc/firewall.user" and Save & Apply.').format(targetFwFile);
				} else if (isFw4 && curFwMode === 'firewall_user') {
					fwStatusText = _('Written to %s, but not loaded by kernel! Please switch "fw4 Firewall Rule Mode" to "/etc/nftables.d/" and Save & Apply.').format(targetFwFile);
				} else {
					fwStatusText = _('Written to %s, but not loaded by kernel! Please check if the firewall service is running properly.').format(targetFwFile);
				}
			} else {
				fwStatusColor = '#f0ad4e';
				fwStatusText = _('No blocking rules found in %s (Please ensure Save & Apply was clicked)').format(targetFwFile);
			}

			var preBaseStyle = 'background:#f5f5f5; padding:8px 10px; border:1px solid #e3e3e3; border-radius:4px; font-family:monospace; font-size:12px; line-height:1.45; white-space:pre; overflow-x:auto; overflow-y:auto; margin-bottom:10px;';

			var modalNode = ui.showModal(_('Self-Test Results'), [
				E('div', { 'style': 'margin-bottom: 6px;' }, [
					E('strong', {}, _('1. DNS Hijacking Status:')),
					E('span', { 'style': 'color:' + (dnsOk ? 'green' : 'red') + '; font-weight:bold;' },
						dnsOk ? _('Normal (All %d domains resolved to %s)').format(curDomains.length, curSpoofIp) : _('Abnormal (Target IP not matched; check global DNS redirect or proxy hijacking)'))
				]),
				E('pre', { 'style': preBaseStyle + 'max-height:185px;' }, dnsOut || _('No output')),

				E('div', { 'style': 'margin-bottom: 6px;' }, [
					E('strong', {}, _('2. HTTP Spoof Status:')),
					E('span', { 'style': 'color:' + (httpOk ? 'green' : 'red') + '; font-weight:bold;' },
						httpOk ? _('Normal (Returned 200 OK with exact 2-byte body "ok")') : _('Abnormal (Unexpected status or body length; current bytes: %s)').format(bodyLen))
				]),
				E('pre', { 'style': preBaseStyle + 'max-height:165px;' },
					(httpHeader ? httpHeader + '\n\n[Body: "' + body + '" | Bytes: ' + bodyLen + ']' : rawOut || _('No output'))),

				E('div', { 'style': 'margin-bottom: 6px;' }, [
					E('strong', {}, _('3. Port 80 Usage Check:')),
					E('span', { 'style': 'color:' + portStatusColor + '; font-weight:bold;' }, portStatusText)
				]),
				E('pre', { 'style': preBaseStyle + 'max-height:80px;' },
					portOwner || _('No port 80 listener records detected')),

				E('div', { 'style': 'margin-bottom: 6px;' }, [
					E('strong', {}, _('4. Firewall Blocking Rules:')),
					E('span', { 'style': 'color:' + fwStatusColor + '; font-weight:bold;' }, fwStatusText)
				]),
				E('pre', { 'style': preBaseStyle + 'max-height:150px;' },
					fwActiveRules || _('No active Switch 2 blocking rules found in kernel firewall')),

				E('div', { 'class': 'right', 'style': 'margin-top: 12px;' }, [
					E('button', {
						'class': 'btn cbi-button-neutral',
						'click': ui.hideModal
					}, _('Close'))
				])
			]);

			if (modalNode) {
				modalNode.style.maxWidth = '860px';
				modalNode.style.width = '92vw';
			}
		}).catch(function(err) {
			ui.hideModal();
			ui.addNotification(null, E('p', _('Self-test execution failed: ') + err.message), 'error');
		});
	},
	render: function(data) {
		var isFw4 = data[2];
		var netDefaults = this.detectNetworkDefaults();
		var m, s, o, enableOpt, forceDhcpOpt, lanOpt, spoofOpt, domainOpt, fwModeOpt;

		m = new form.Map('switch2-block', _('Nintendo Switch 2 Connection Spoof & Update Blocker'),
			_('Emulate Nintendo connection test responses via isolated dnsmasq and uHTTPd instances so Switch 2 / Switch 1 can pass network checks without external internet access.') + '<br/>' +
			'<strong style="color:#d9534f;">' + _('Note:') + '</strong> ' +
			_('If proxy plugins (SSR Plus+ / PassWall / OpenClash) are enabled, add the Nintendo test domain and Spoof Helper IP to the bypass whitelist to prevent traffic hijacking.'));

		s = m.section(form.NamedSection, 'global', 'global', _('Basic Network Isolation Settings'));
		s.anonymous = true;

		o = s.option(form.DummyValue, '_fw_status', _('Current Firewall Architecture'));
		o.rawhtml = true;
		o.cfgvalue = function() {
			return isFw4
				? '<span style="color:#5cb85c; font-weight:bold;">fw4 (nftables)</span>'
				: '<span style="color:#f0ad4e; font-weight:bold;">' + _('fw3 (iptables) - Auto-uses /etc/firewall.user') + '</span>';
		};

		enableOpt = s.option(form.Flag, 'enabled', _('Enable Spoof & Update Blocker'),
			_('Automatically configure helper interface, isolate dnsmasq/uHTTPd listeners, and inject firewall blocking rules; restores original settings cleanly when disabled.'));
		enableOpt.rmempty = false;

		forceDhcpOpt = s.option(form.Flag, 'force_dhcp', _('Enable Force DHCP'),
			_('Recommended for bypass/secondary gateway mode. Forces main_dns to handle LAN DHCP (sets dhcp.lan.force=1) so the main router will not assign wrong DNS.'));
		forceDhcpOpt.default = '0';
		forceDhcpOpt.rmempty = false;

		if (isFw4) {
			fwModeOpt = s.option(form.ListValue, 'fw_mode', _('fw4 Firewall Rule Mode'),
				_('Official OpenWrt 22.03+ recommends Native Rule Directory; custom firmware like LEDE recommends Custom Rules File.'));
			fwModeOpt.value('nftables_d', _('Write to /etc/nftables.d/ native directory (Official OpenWrt)'));
			fwModeOpt.value('firewall_user', _('Write to /etc/firewall.user custom script (Recommended for LEDE)'));
			fwModeOpt.default = 'firewall_user';
			fwModeOpt.rmempty = false;
		}

		lanOpt = s.option(form.Value, 'lan_ip', _('Router Main LAN IP'),
			_('IP address for main dnsmasq and LuCI web management (auto-detected from LAN interface).'));
		lanOpt.datatype = 'ip4addr';
		if (netDefaults.lanIp) {
			lanOpt.default = netDefaults.lanIp;
			lanOpt.placeholder = netDefaults.lanIp;
		}
		lanOpt.rmempty = false;

		spoofOpt = s.option(form.Value, 'spoof_ip', _('Switch Spoof Helper IP'),
			_('Virtual alias IP created on br-lan. Must be in the same subnet as Main LAN IP and not identical.'));
		spoofOpt.datatype = 'ip4addr';
		if (netDefaults.spoofIp) {
			spoofOpt.default = netDefaults.spoofIp;
			spoofOpt.placeholder = netDefaults.spoofIp;
		}
		spoofOpt.rmempty = false;
		spoofOpt.validate = function(section_id, value) {
			var lanVal = lanOpt.formvalue(section_id);
			if (lanVal && value === lanVal) {
				return _('Spoof Helper IP cannot be identical to Router Main LAN IP!');
			}
			if (lanVal && value) {
				var p1 = lanVal.split('.').slice(0, 3).join('.');
				var p2 = value.split('.').slice(0, 3).join('.');
				if (p1 !== p2) {
					return _('Spoof Helper IP must be in the same /24 subnet as Main LAN IP (e.g., %s.254)!').format(p1);
				}
			}
			return true;
		};

		domainOpt = s.option(form.DynamicList, 'test_domain', _('Nintendo Connection Test Domains'),
			_('Supports multiple domains (e.g. Switch 2: ctest.p01.ctest.srv.nintendo.net, Switch 1: ctest.cdn.nintendo.net).'));
		domainOpt.datatype = 'hostname';
		domainOpt.default = ['ctest.p01.ctest.srv.nintendo.net'];
		domainOpt.placeholder = 'ctest.p01.ctest.srv.nintendo.net';
		domainOpt.rmempty = false;

		o = s.option(form.Button, '_test_btn', _('Service Connectivity Self-Test'),
			_('After clicking Save & Apply, click here to verify DNS hijacking, HTTP 2-byte response, port 80 usage, and firewall rules.'));
		o.inputtitle = _('Run Connectivity Self-Test');
		o.inputstyle = 'apply';
		o.onclick = L.bind(function() {
			return this.handleTestSpoof(m, enableOpt, forceDhcpOpt, lanOpt, spoofOpt, domainOpt, fwModeOpt, isFw4, netDefaults);
		}, this);

		var s2 = m.section(form.GridSection, 'device', _('Controlled Devices (MAC-based DNS & Firewall Isolation)'),
			_('Listed devices set to Automatic (DHCP) will receive the dedicated spoof DNS and optional WAN isolation. If this list is left empty while enabled, the plugin runs in Manual DNS Mode: you must manually set a static IP and use the Spoof Helper IP as DNS on your Switch (note: firewall-level MAC blocking will not apply).'));
		s2.addremove = true;
		s2.anonymous = true;

		o = s2.option(form.Value, 'name', _('Device Name'));
		o.placeholder = 'Switch2';
		o.rmempty = false;

		var macOpt = s2.option(form.Value, 'mac', _('MAC Address'));
		macOpt.datatype = 'macaddr';
		macOpt.placeholder = '11:22:33:44:55:66';
		macOpt.rmempty = false;

		o = s2.option(form.Value, 'ip', _('Static IP (Optional)'),
			_('Leave blank for dynamic DHCP assignment with dedicated spoof DNS.'));
		o.datatype = 'ip4addr';
		o.placeholder = netDefaults.prefix ? _('Auto-assign (e.g., %s.x)').format(netDefaults.prefix) : _('Auto-assign');
		o.rmempty = true;
		o.validate = function(section_id, value) {
			if (!value) return true;
			var lanVal = lanOpt.formvalue('global');
			var spoofVal = spoofOpt.formvalue('global');
			if (value === lanVal || value === spoofVal) {
				return _('Static IP cannot be identical to Main LAN IP or Spoof Helper IP!');
			}
			if (lanVal) {
				var p1 = lanVal.split('.').slice(0, 3).join('.');
				var p2 = value.split('.').slice(0, 3).join('.');
				if (p1 !== p2) {
					return _('Static IP must be in the same subnet as Main LAN IP (%s.x)!').format(p1);
				}
			}
			return true;
		};

		o = s2.option(form.Flag, 'block_wan', _('Block WAN via Firewall'),
			_('Inject firewall rules to block IPv6 ICMPv6 and all IPv4/IPv6 WAN forwarding for this MAC to prevent hardcoded IP leaks.'));
		o.default = '1';
		o.rmempty = false;

		var origSaveApply = this.handleSaveApply;
		this.handleSaveApply = function(ev, mode) {
			var curEnabled = enableOpt.formvalue('global');
			var curSpoofIp = String(spoofOpt.formvalue('global') || '').trim();
			if (curEnabled === '1') {
				var devSections = uci.sections('switch2-block', 'device');
				var hasDefaultMac = false;
				var validCount = 0;

				for (var i = 0; i < devSections.length; i++) {
					var sid = devSections[i]['.name'];
					var valMac = macOpt.formvalue(sid);
					if (valMac === undefined || valMac === null) {
						valMac = devSections[i].mac;
					}
					var cleanMac = String(valMac || '').trim().toUpperCase();
					if (cleanMac === '11:22:33:44:55:66') {
						hasDefaultMac = true;
						break;
					}
					if (cleanMac !== '') {
						validCount++;
					}
				}

				if (hasDefaultMac) {
					ui.addNotification(null, E('p', { 'style': 'font-weight:bold;' },
						_('Default example MAC (11:22:33:44:55:66) is still in the device list! Please replace it with your real Switch MAC address before saving.')
					), 'error');
					return Promise.reject(new Error('Default example MAC not allowed'));
				}

				if (validCount === 0) {
					ui.addNotification(null, E('p', {},
						_('No MAC address configured. Running in Manual DNS Mode: please manually assign a static IP on your Switch and set its DNS to %s. Note that firewall-level WAN blocking is inactive without a MAC address.').format(curSpoofIp || 'Spoof Helper IP')
					), 'info');
				}
			}
			return origSaveApply.call(this, ev, mode);
		};

		return m.render();

	}
});
