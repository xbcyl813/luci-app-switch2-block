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

	normalizeDomains: function(rawDomains, fallbackList) {
		var arr = Array.isArray(rawDomains) ? rawDomains : (rawDomains ? [rawDomains] : []);
		var res = [];
		for (var i = 0; i < arr.length; i++) {
			var d = String(arr[i] || '').trim();
			if (d !== '' && res.indexOf(d) === -1) {
				res.push(d);
			}
		}
		return res.length > 0 ? res : (fallbackList || []);
	},

	hasUnsavedDeviceChanges: function(devGridSection) {
		var changes = uci.changes();
		if (changes && changes['switch2-block']) {
			var secChanges = changes['switch2-block'];
			for (var k in secChanges) {
				if (Object.prototype.hasOwnProperty.call(secChanges, k)) {
					var st = uci.get('switch2-block', k);
					if (!st || st['.type'] === 'device') {
						return true;
					}
				}
			}
		}
		if (devGridSection && typeof devGridSection.cfgsections === 'function') {
			var curSids = devGridSection.cfgsections();
			var savedSids = (uci.sections('switch2-block', 'device') || []).map(function(s) { return s['.name']; });
			if (curSids.length !== savedSids.length) {
				return true;
			}
		}
		return false;
	},

	handleTestSpoof: function(m, enableOpt, forceDhcpOpt, lanOpt, spoofOpt, domainOpt, fwModeOpt, devSection, isFw4, netDefaults) {
		var savedEnabled = uci.get('switch2-block', 'global', 'enabled') || '0';
		var savedForceDhcp = uci.get('switch2-block', 'global', 'force_dhcp') || '0';
		var savedLanIp = uci.get('switch2-block', 'global', 'lan_ip') || netDefaults.lanIp || '';
		var savedSpoofIp = uci.get('switch2-block', 'global', 'spoof_ip') || netDefaults.spoofIp || '';
		var savedFwMode = uci.get('switch2-block', 'global', 'fw_mode') || 'firewall_user';
		var savedDomains = this.normalizeDomains(
			uci.get('switch2-block', 'global', 'test_domain'),
			['ctest.p01.ctest.srv.nintendo.net']
		);

		var curEnabled = enableOpt ? enableOpt.formvalue('global') : savedEnabled;
		var curForceDhcp = forceDhcpOpt ? forceDhcpOpt.formvalue('global') : savedForceDhcp;
		var curLanIp = lanOpt ? (lanOpt.formvalue('global') || savedLanIp) : savedLanIp;
		var curSpoofIp = spoofOpt ? (spoofOpt.formvalue('global') || savedSpoofIp) : savedSpoofIp;
		var curFwMode = fwModeOpt ? (fwModeOpt.formvalue('global') || savedFwMode) : savedFwMode;
		var curDomains = this.normalizeDomains(
			domainOpt ? domainOpt.formvalue('global') : savedDomains,
			['ctest.p01.ctest.srv.nintendo.net']
		);

		if (curEnabled !== '1') {
			ui.addNotification(null, E('p', _('Spoof & Blocker is currently disabled. Please enable it and click Save & Apply first.')), 'warning');
			return;
		}

		var pendingChanges = uci.changes();
		var hasPendingUci = pendingChanges && pendingChanges['switch2-block'] && Object.keys(pendingChanges['switch2-block']).length > 0;

		if (hasPendingUci ||
			this.hasUnsavedDeviceChanges(devSection) ||
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

		var effectiveFwMode = isFw4 ? curFwMode : 'firewall_user';
		var targetFwFile = (isFw4 && effectiveFwMode === 'nftables_d')
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
			var dnsOut = '', aaaaCheckOut = '', httpHeader = '', bodyLen = '0', body = '', portOwner = '', fwActiveRules = '';

			var mDns = rawOut.match(/=== DNS_RESULT ===\n([\s\S]*?)\n=== DNS_AAAA_CHECK ===/);
			var mAaaa = rawOut.match(/=== DNS_AAAA_CHECK ===\n([\s\S]*?)\n=== HTTP_HEADER ===/);
			var mHdr = rawOut.match(/=== HTTP_HEADER ===\n([\s\S]*?)\n=== HTTP_BODY_LEN ===/);
			var mLen = rawOut.match(/=== HTTP_BODY_LEN ===\n([\s\S]*?)\n=== HTTP_BODY ===/);
			var mBody = rawOut.match(/=== HTTP_BODY ===\n([\s\S]*?)\n=== HTTP_PORT_OWNER ===/);
			var mPort = rawOut.match(/=== HTTP_PORT_OWNER ===\n([\s\S]*?)\n=== FW_ACTIVE_RULES ===/);
			var mFw = rawOut.match(/=== FW_ACTIVE_RULES ===\n([\s\S]*)$/);

			if (mDns && mDns[1]) dnsOut = mDns[1].trim();
			if (mAaaa && mAaaa[1]) aaaaCheckOut = mAaaa[1].trim();
			if (mHdr && mHdr[1]) httpHeader = mHdr[1].trim();
			if (mLen && mLen[1]) bodyLen = mLen[1].trim();
			if (mBody && mBody[1]) body = mBody[1].replace(/\n$/, '');
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

			/* 兼容不同 nslookup 输出格式：逐段检查是否包含目标 spoofIp */
			var dnsOk = curDomains.length > 0 && dnsOut.indexOf(curSpoofIp) !== -1;
			if (dnsOk && curDomains.length > 1) {
				for (var k = 0; k < curDomains.length; k++) {
					if (dnsOut.indexOf(curDomains[k]) === -1) {
						dnsOk = false;
						break;
					}
				}
			}

			/* 检查 IPv6 AAAA 域名解析是否已屏蔽，并根据实际设置的 curSpoofIp 动态格式化结果 */
			var ipv6Blocked = aaaaCheckOut.indexOf('IPV6_BLOCKED=1') !== -1;
			var dnsStatusText;
			if (dnsOk && ipv6Blocked) {
				dnsStatusText = _('Normal (All %d domains resolved to %s), IPv6 DNS resolution blocked').format(curDomains.length, curSpoofIp);
			} else if (dnsOk && !ipv6Blocked) {
				dnsStatusText = _('Normal (All %d domains resolved to %s), but IPv6 DNS resolution is NOT blocked').format(curDomains.length, curSpoofIp);
			} else {
				dnsStatusText = _('Abnormal (Target IP not matched; check global DNS redirect or proxy hijacking)');
			}

			var httpOk = httpHeader.indexOf('200 OK') !== -1 && body === 'ok' && bodyLen === '2';

			var portStatusColor, portStatusText;
			var spoofBound = false;
			var conflictProc = '';
			if (portOwner) {
				var pLines = portOwner.split('\n');
				for (var pl = 0; pl < pLines.length; pl++) {
					var line = pLines[pl].trim();
					if (!line) continue;
					var hitsSpoof = (line.indexOf(curSpoofIp + ':80') !== -1);
					var hitsWildcard = (line.indexOf('0.0.0.0:80') !== -1 || line.indexOf('*:80') !== -1);
					if (hitsSpoof) {
						if (line.indexOf('uhttpd') !== -1) {
							spoofBound = true;
						} else {
							conflictProc = line;
						}
					} else if (hitsWildcard && line.indexOf('uhttpd') === -1) {
						conflictProc = line;
					}
				}
			}

			if (conflictProc) {
				var procName = _('Other Web Service');
				var pStart = conflictProc.indexOf('(("');
				if (pStart !== -1) {
					var pEnd = conflictProc.indexOf('"', pStart + 3);
					if (pEnd !== -1) {
						procName = conflictProc.substring(pStart + 3, pEnd);
					}
				}
				portStatusColor = '#d9534f';
				portStatusText = _('Conflict: Port 80 is globally occupied by "%s"! Please bind it only to Main LAN IP (%s:80)').format(procName, curLanIp);
			} else if (spoofBound) {
				portStatusColor = 'green';
				portStatusText = _('Normal (Exclusively bound by uHTTPd on %s:80, no port conflict)').format(curSpoofIp);
			} else {
				portStatusColor = '#d9534f';
				portStatusText = _('Abnormal: No listener detected on %s:80 (uHTTPd helper instance not running)').format(curSpoofIp);
			}

			var fwStatusColor, fwStatusText;
			if (!hasBlockDevice) {
				fwStatusColor = 'red';
				fwStatusText = _('Skipped (No device enabled for WAN blocking)');
			} else if (fwRuleInFile && fwActiveCount > 0) {
				fwStatusColor = 'green';
				fwStatusText = _('Written to %s and active in kernel firewall (%d rules)').format(targetFwFile, fwActiveCount);
			} else if (fwRuleInFile && fwActiveCount === 0) {
				fwStatusColor = '#d9534f';
				if (isFw4 && effectiveFwMode === 'nftables_d') {
					fwStatusText = _('Written to %s, but not loaded by kernel! Please switch "fw4 Firewall Rule Mode" to "/etc/firewall.user" and Save & Apply.').format(targetFwFile);
				} else if (isFw4 && effectiveFwMode === 'firewall_user') {
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
					E('span', { 'style': 'color:' + ((dnsOk && ipv6Blocked) ? 'green' : 'red') + '; font-weight:bold;' }, dnsStatusText)
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
		var m, s, o, enableOpt, forceDhcpOpt, lanOpt, spoofOpt, domainOpt, fwModeOpt, s2;

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
			return this.handleTestSpoof(m, enableOpt, forceDhcpOpt, lanOpt, spoofOpt, domainOpt, fwModeOpt, s2, isFw4, netDefaults);
		}, this);

		s2 = m.section(form.GridSection, 'device', _('Controlled Devices (MAC-based DNS & Firewall Isolation)'),
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
			var self = this;
			var curEnabled = enableOpt.formvalue('global');
			var curSpoofIp = String(spoofOpt.formvalue('global') || '').trim();

			if (curEnabled === '1') {
				var devSections = s2.cfgsections ? s2.cfgsections() : [];
				var hasDefaultMac = false;
				var validCount = 0;

				for (var i = 0; i < devSections.length; i++) {
					var sid = devSections[i];
					var valMac = macOpt.formvalue(sid);
					if (valMac === undefined || valMac === null) {
						var secObj = uci.get('switch2-block', sid);
						valMac = secObj ? secObj.mac : '';
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
					ui.showModal(_('Configuration Error'), [
						E('p', { 'style': 'font-weight:bold; font-size:14px; line-height:1.6;' },
							_('Default example MAC (11:22:33:44:55:66) is still in the device list! Please replace it with your real Switch MAC address before saving.')
						),
						E('div', { 'class': 'right', 'style': 'margin-top: 15px;' }, [
							E('button', {
								'class': 'btn cbi-button-negative important',
								'click': ui.hideModal
							}, _('Close'))
						])
					]);
					return Promise.reject(new Error('Default example MAC not allowed'));
				}

				if (validCount === 0) {
					return new Promise(function(resolve, reject) {
						ui.showModal(_('Manual DNS Mode Notice'), [
							E('p', { 'style': 'font-size:14px; line-height:1.6;' },
								_('No MAC address configured. Running in Manual DNS Mode: please manually assign a static IP on your Switch and set its DNS to %s. Note that firewall-level WAN blocking is inactive without a MAC address.').format(curSpoofIp || 'Spoof Helper IP')
							),
							E('div', { 'class': 'right', 'style': 'margin-top: 15px;' }, [
								E('button', {
									'class': 'btn cbi-button-neutral',
									'style': 'margin-right: 8px;',
									'click': function() {
										ui.hideModal();
										reject(new Error('User cancelled manual DNS mode save'));
									}
								}, _('Cancel')),
								E('button', {
									'class': 'btn cbi-button-action important',
									'click': function() {
										ui.hideModal();
										resolve(origSaveApply.call(self, ev, mode));
									}
								}, _('Confirm & Save'))
							])
						]);
					});
				}
			}
			return origSaveApply.call(self, ev, mode);
		};

		return m.render();
	}
});
