#!/usr/bin/env python3
"""Generates the test cases of the Watchpost rules (cases/*.log). Usage: python3 generate-cases.py cases

Each file: comments (description, "expected: <rule id>" for the LAST line), then one or more
event lines (the first ones prime the correlation rules).
@@DNS_HOST@@ is replaced at run time by the expected private DNS host (CDB list)."""
import json, os, sys
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
for f in os.listdir(out):
    if f.endswith('.log'): os.remove(os.path.join(out, f))
seq = [1000]
def ev(typ, data, sev=0, dev="dev_7k2m9q", name="phone", source=None):
    seq[0] += 1
    v = {"device_id": dev, "device_name": name, "id": "01JTEST%019d" % seq[0],
        "ts": "2026-11-15T21:43:03.974Z", "received_at": "2026-11-15T21:43:05.120Z", "seq": seq[0],
        "type": typ, "domain": typ.split('.')[0], "sev": sev}
    if source:  # events produced by the collector (commands §8, tracking §9, detections §11.3)
        v["seq"] = 0; v["source"] = source
    v["data"] = data
    return json.dumps({"watchpost": v}, ensure_ascii=False, separators=(',', ':'))
CMD = "01JCQ8Z3K4M5N6P7Q8R9S0T1V2"
def issued(typ, params=None, sev=0, **kw):
    d = {"command_id": CMD, "type": typ, "signed": typ in ("lock", "wipe", "clear_lock_message"), "created_by": "admin",
         "expires_at": "2026-11-23T10:00:00.000Z", "params": params or {}}
    d.update(kw)
    return ev("command.issued", d, sev, source="server")
def result(typ, status, detail=None, sev=0):
    d = {"command_id": CMD, "type": typ, "status": status, "signed": typ in ("lock", "wipe", "clear_lock_message")}
    if detail: d["detail"] = detail
    return ev("command.result", d, sev)
def agh(qh, filtered=False, listid=10, ip="203.0.113.7", cp="dot"):
    d = {"T": "2026-11-15T22:30:36.905394867Z", "QH": qh, "QT": "A", "QC": "IN", "CP": cp,
         "Answer": "PjuBgAABAAEAAAAAD2FwcC1tZWFzdXJlbWVudANjb20AAAEAAcAMAAEAAQAAAAoABAAAAAA=", "IP": ip}
    if filtered:
        d["Result"] = {"Rules": [{"Text": "||%s^" % qh, "FilterListID": listid}], "Reason": 3, "IsFiltered": True}
    else:
        d["Result"] = {}; d["Upstream"] = "https://dns.quad9.net:443/dns-query"
    d["Elapsed"] = 186617
    return json.dumps(d, separators=(',', ':'))
# v1.2: detections (contract §11.3), applications of the simulator scenarios
TORCH = ("com.flashlight.pro.tools", "Torch Pro")
TROJAN = ("com.android.systemupdate.service", "System Update")
SPY = ("com.android.battery.service", "Battery Service")
VAULT = ("com.gallery.vault.hide", "Photo Vault")
PUZZLE = ("com.puzzle.relax.free", "Puzzle Relax")
CLEANER = ("com.cleaner.boost.free", "Cleaner Boost")
FASTVPN = ("com.fastvpn.browser", "Fast Browser")
BROWSER = ("com.sec.android.app.sbrowser", "Samsung Internet")
DAY = ("2026-11-15T00:00:00.000Z", "2026-11-16T00:00:00.000Z")
INSTALL_WINDOW = ("2026-11-15T12:42:07.204Z", "2026-11-16T12:42:07.204Z")
def det(kind, app, evidence, sev=3, update=False, window=DAY, recurring=False):
    d = {"evidence": evidence, "label": app[1], "package": app[0], "summary": "%s: test finding (%s)" % (app[1], kind),
         "window_from": window[0], "window_to": window[1]}
    if recurring:
        d["recurring"] = True
    if update:
        d["update"] = True; d["detection_id"] = "01M7JPAP1R31CWDX8J7CFDY1M7"
    return ev("detect." + kind, d, sev, source="server")
def newapp(caps, high, reasons, score, level="high"):
    e = {"capabilities": caps, "from_store": False, "high_risk": high, "installed_at": INSTALL_WINDOW[0],
         "installer": "com.google.android.packageinstaller", "level": level, "reasons": reasons, "score": score}
    if caps:
        e["minutes_to_first_capability"] = 3
    return e
def risk(app, level, score, reasons, installer, vc=7):
    return ev("app.risk", {"from_store": installer in ("com.android.vending", "com.sec.android.app.samsungapps"), "installer": installer,
        "label": app[1], "level": level, "package": app[0], "reasons": reasons, "score": score, "version_code": vc},
        {"low": 0, "medium": 1, "high": 2}[level])
def guard(action, key, target, permission=None, sev=None, ok=True):
    d = {"action": action, "ok": ok, "profile": "guard:" + key, "target": target}
    if permission: d["permission"] = permission
    if not ok: d["error"] = "SecurityException"
    return ev("security.policy", d, 1 if sev is None else sev)
def pc(field, old, new, sev=0):
    return ev("security.posture_change", {"field": field, "old": old, "new": new}, sev)
def watch(o):
    return json.dumps({"watchpost_watch": o}, separators=(',', ':'))
GOOD = {"security_patch": "2026-10-01", "patch_age_days": 45, "encrypted": True, "lock_secure": True,
        "adb_enabled": False, "adb_wifi_enabled": False, "dev_options": False, "unknown_sources": False,
        "private_dns_mode": "hostname", "private_dns_host": "@@DNS_HOST@@", "always_on_vpn": False,
        "device_owner": True, "verified_boot_state": "green", "user_ca_certs": [], "play_protect": True,
        "usb_data_signaling": True}
def posture(**kw):
    d = dict(GOOD); d.update(kw); return ev("security.posture", d)
SA = {"accessibility_services": [], "notification_listeners": ["com.google.android.gms/.NotifListener"],
      "device_admins": ["io.github.erwsim.watchpost/.AdminReceiver"], "overlay_apps": [], "unknown_sources_apps": [],
      "usage_access_apps": ["io.github.erwsim.watchpost"], "vpn_apps": [], "default_apps": {"browser": "org.mozilla.firefox"}}
def sa(**kw):
    d = dict(SA); d.update(kw); return ev("app.special_access", d)
def slog(tag, fields=None, level="info"):
    return ev("security.log", {"tag": tag, "level": level, "log_id": 12345, "fields": fields or {}})
H = "15b9d7d0c1f9e0a3b8f6c2d4e5a7b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6"
cases = [
 ("100100", "ordinary-event", "Normal position: base rule, level 0", [ev("location.fix", {"lat": 48.8566, "lon": 2.3522, "acc_m": 12.5, "provider": "gps", "mock": False, "fix_ts": "2026-11-15T21:43:03Z", "location": {"lat": 48.8566, "lon": 2.3522}})]),
 ("100101", "derived-inventory-line", "Inventory item (line derived from the export)", [ev("app.inventory.app", {"package": "org.mozilla.firefox", "installer": "com.android.vending", "system": False, "part": 1, "parts": 3})]),
 ("100110", "agent-tamper", "Agent tampering", [ev("agent.tamper", {"kind": "permission_revoked", "detail": "ACCESS_FINE_LOCATION"}, 3)]),
 ("100111", "agent-stopped", "Agent stopped", [ev("agent.stopped", {"reason": "user", "agent_version": "1.0.0"})]),
 ("100112", "agent-buffer-full", "Buffer purge", [ev("agent.buffer_overflow", {"dropped": 1200, "oldest_ts": "2026-10-01T00:00:00Z", "newest_ts": "2026-10-03T00:00:00Z"}, 2)]),
 ("100113", "agent-collector-error", "Error of a collector", [ev("agent.collector_error", {"collector": "net.cell", "error": "SecurityException"}, 1)]),
 ("100114", "agent-setting", "Setting changed (harmless)", [ev("agent.config_changed", {"key": "ui.theme", "old": "light", "new": "dark"})]),
 ("100115", "agent-collection-disabled", "Collection disabled in the agent", [ev("agent.config_changed", {"key": "collector.location.enabled", "old": True, "new": False}, 1)]),
 ("100116", "agent-device-owner-lost", "Heartbeat without Device Owner", [ev("agent.heartbeat", {"battery_pct": 80, "charging": False, "uptime_ms": 360000, "queue_depth": 0, "queue_bytes": 0, "dropped_total": 0, "device_owner": False, "collectors": {"location": "running", "net.dns": "unavailable"}, "last_upload_ts": "2026-11-15T21:40:00Z"}, 1)]),
 ("100100", "agent-normal-heartbeat", "Normal heartbeat (Device Owner): no alert", [ev("agent.heartbeat", {"battery_pct": 80, "charging": True, "device_owner": True, "collectors": {"location": "running"}})]),
 ("100120", "clock-changed", "Clock changed by 2 h", [ev("device.time_changed", {"delta_ms": -7200000}, 1)]),
 ("100100", "clock-small-drift", "Clock correction of 1.5 s: no alert", [ev("device.time_changed", {"delta_ms": 1500})]),
 ("100121", "usb-adb", "USB with ADB", [ev("device.usb", {"connected": True, "configured": True, "functions": ["mtp", "adb"]}, 1)]),
 ("100130", "mock-location", "Simulated position", [ev("location.fix", {"lat": 48.85, "lon": 2.35, "acc_m": 3, "provider": "gps", "mock": True, "location": {"lat": 48.85, "lon": 2.35}}, 2)]),
 ("100140", "cellular-other", "Unclassified cellular anomaly", [ev("net.cell_security", {"kind": "other", "detail": "x"}, 2)]),
 ("100141", "cellular-2g", "2G downgrade", [ev("net.cell_security", {"kind": "downgrade_2g", "detail": "LTE->GSM"}, 2)]),
 ("100142", "cellular-null-cipher", "Null cipher", [ev("net.cell_security", {"kind": "null_cipher", "detail": "A5/0"}, 3)]),
 ("100143", "cellular-imsi", "Identifier disclosure", [ev("net.cell_security", {"kind": "identifier_disclosure", "detail": "IMSI"}, 2)]),
 ("100145", "ble-tracker", "BLE tracker following the device", [ev("net.ble_tracker", {"address": "c4:5a:11:22:33:44", "kind": "airtag", "rssi": -60, "first_seen": "2026-11-15T19:00:00Z", "sightings": 14}, 2)]),
 ("100146", "wifi-open", "Open Wi-Fi", [ev("net.wifi", {"event": "connected", "ssid": "Station-WiFi", "bssid": "aa:bb:cc:dd:ee:ff", "rssi": -50, "freq_mhz": 2437, "security": "open"})]),
 ("100100", "wifi-wpa3", "WPA3 Wi-Fi: no alert", [ev("net.wifi", {"event": "connected", "ssid": "Home", "security": "wpa3"})]),
 ("100147", "network-without-private-dns", "Network without private DNS", [ev("net.connectivity", {"transports": ["wifi"], "validated": True, "metered": False, "vpn": False, "private_dns_active": False, "dns_servers": ["192.168.1.1"]})]),
 ("100148", "dns-telemetry", "Query from an app to a telemetry domain", [ev("net.dns", {"package": "com.example.game", "uid": 10234, "hostname": "app-measurement.com", "addresses": ["0.0.0.0"], "address_count": 1})]),
 ("100148", "dns-telemetry-samsung", "Query to Samsung telemetry", [ev("net.dns", {"package": "com.samsung.android.game.gos", "hostname": "api.gos-gsp.io", "address_count": 0})]),
 ("100100", "dns-ordinary", "Ordinary DNS query", [ev("net.dns", {"package": "org.mozilla.firefox", "hostname": "example.org", "address_count": 2})]),
 ("100150", "app-installed-play", "App installed from the Play Store", [ev("app.installed", {"package": "org.example.app", "version_name": "1.2", "version_code": 12, "installer": "com.android.vending", "signer_sha256": H})]),
 ("100151", "app-installed-outside-store", "App installed by another installer", [ev("app.installed", {"package": "org.example.apk", "version_name": "1.0", "version_code": 1, "installer": "com.google.android.packageinstaller", "signer_sha256": H}, 1)]),
 ("100152", "app-installed-adb", "App installed without an installer (ADB)", [ev("app.installed", {"package": "org.example.adb", "version_name": "1.0", "version_code": 1, "signer_sha256": H}, 1)]),
 ("100153", "app-uninstalled", "App uninstalled", [ev("app.removed", {"package": "org.example.app"})]),
 ("100155", "special-access-daily", "Special access unchanged (a single event)", [sa()]),
 ("100156", "access-accessibility", "New app with an accessibility service", [sa(), sa(accessibility_services=["com.evil.app/.A11yService"])]),
 ("100157", "access-device-admin", "New device administrator", [sa(), sa(device_admins=["io.github.erwsim.watchpost/.AdminReceiver", "com.evil.app/.Admin"])]),
 ("100158", "access-notifications", "New app that reads notifications", [sa(), sa(notification_listeners=["com.google.android.gms/.NotifListener", "com.evil.app/.Listener"])]),
 ("100159", "access-vpn", "New VPN app", [sa(), sa(vpn_apps=["com.evil.vpn"])]),
 ("100155", "special-access-identical", "Two identical states: no alert", [sa(), sa()]),
 ("100160", "permission-microphone", "Microphone permission granted", [ev("app.permission_changed", {"package": "com.example.voice", "permission": "android.permission.RECORD_AUDIO", "granted": True})]),
 ("100100", "permission-revoked", "Permission revoked: no alert", [ev("app.permission_changed", {"package": "com.example.voice", "permission": "android.permission.RECORD_AUDIO", "granted": False})]),
 ("100170", "microphone-used", "Microphone used", [ev("sensor.microphone", {"recording": True, "source": "mic", "package": "com.whatsapp", "silenced": False, "screen_on": True, "locked": False})]),
 ("100171", "camera-used", "Camera used", [ev("sensor.camera", {"camera_id": "1", "in_use": True, "package": "com.whatsapp", "screen_on": True, "locked": False})]),
 ("100180", "unlock-failed", "One unlock failure", [ev("security.keyguard", {"event": "unlock_failed", "failed_attempts": 1}, 1)]),
 ("100181", "unlocks-repeated", "5 failures in less than 10 min", [ev("security.keyguard", {"event": "unlock_failed", "failed_attempts": n}, 1) for n in range(1, 6)]),
 ("100182", "unlocks-consecutive", "12 consecutive failures reported", [ev("security.keyguard", {"event": "unlock_failed", "failed_attempts": 12}, 2)]),
 ("100185", "ca-added", "User CA added", [ev("security.ca_cert", {"event": "added", "sha256": H, "subject": "CN=Proxy MITM"}, 2)]),
 ("100186", "ca-removed", "User CA removed", [ev("security.ca_cert", {"event": "removed", "sha256": H, "subject": "CN=Proxy MITM"}, 2)]),
 ("100187", "policy-failure", "Failure of a Device Owner action", [ev("security.policy", {"action": "package_disabled", "target": "com.samsung.android.bixby.agent", "profile": "balanced", "ok": False, "error": "SecurityException"}, 1)]),
 ("100100", "policy-ok", "Device Owner action succeeded: no alert", [ev("security.policy", {"action": "private_dns_set", "target": "@@DNS_HOST@@", "profile": "balanced", "ok": True})]),
 ("100190", "posture-healthy", "Healthy posture: no alert", [posture()]),
 ("100191", "posture-boot-orange", "Verified boot orange", [posture(verified_boot_state="orange", adb_enabled=True)]),
 ("100192", "posture-not-encrypted", "Storage not encrypted", [posture(encrypted=False)]),
 ("100193", "posture-not-device-owner", "Not Device Owner", [posture(device_owner=False)]),
 ("100194", "posture-private-dns-off", "Private DNS disabled", [posture(private_dns_mode="off", private_dns_host=None)]),
 ("100194", "posture-private-dns-auto", "Private DNS automatic (not strict)", [posture(private_dns_mode="opportunistic", private_dns_host=None)]),
 ("100195", "posture-private-dns-other-host", "Private DNS to another host", [posture(private_dns_host="dns.adguard-dns.com")]),
 ("100196", "posture-adb-wifi", "Wireless ADB", [posture(adb_wifi_enabled=True, adb_enabled=True, dev_options=True)]),
 ("100197", "posture-adb", "ADB enabled", [posture(adb_enabled=True, dev_options=True)]),
 ("100198", "posture-no-lock", "No secure lock", [posture(lock_secure=False)]),
 ("100199", "posture-user-ca", "User CA present", [posture(user_ca_certs=[H])]),
 ("100200", "posture-patch-6-months", "Patch older than 6 months", [posture(patch_age_days=200)]),
 ("100201", "posture-unknown-sources", "Unknown sources allowed", [posture(unknown_sources=True)]),
 ("100202", "posture-patch-3-months", "Patch older than 3 months", [posture(patch_age_days=120)]),
 ("100203", "posture-play-protect", "Play Protect disabled", [posture(play_protect=False)]),
 ("100204", "posture-dev-options", "Developer options", [posture(dev_options=True)]),
 ("100210", "securitylog-ordinary", "Ordinary security log", [slog("app_process_start", {"process": "com.android.chrome", "start_time": 1794774875127, "uid": 10100, "pid": 30412, "seinfo": "default:targetSdkVersion=35:complete", "apk_sha256": H})]),
 ("100211", "securitylog-adb-shell", "Interactive ADB shell", [slog("adb_shell_interactive")]),
 ("100212", "securitylog-adb-command", "ADB command", [slog("adb_shell_cmd", {"command": "pm list packages"})]),
 ("100213", "securitylog-adb-file", "ADB file transfer", [slog("sync_recv_file", {"path": "/sdcard/DCIM/x.jpg"})]),
 ("100214", "securitylog-keyguard-failure", "Authentication failure (log)", [slog("keyguard_dismiss_auth_attempt", {"success": False, "strength": 1})]),
 ("100215", "securitylog-keyguard-repeated", "5 failures (log)", [slog("keyguard_dismiss_auth_attempt", {"success": False, "strength": 1}) for _ in range(5)]),
 ("100216", "securitylog-ca-installed", "CA installed (log)", [slog("cert_authority_installed", {"success": True, "subject": "CN=Proxy MITM", "user_id": 0})]),
 ("100217", "securitylog-stopped", "Logging stopped", [slog("logging_stopped")]),
 ("100218", "securitylog-buffer-critical", "Log buffer almost full", [slog("log_buffer_size_critical")]),
 ("100219", "securitylog-key-violation", "Key integrity violation", [slog("key_integrity_violation", {"alias": "watchpost_upload_key", "uid": 10301})]),
 ("100220", "securitylog-crypto-self-test", "Crypto self-test failure", [slog("crypto_self_test_completed", {"success": False})]),
 ("100221", "securitylog-wipe-failure", "Wipe failure", [slog("wipe_failure", {"arg0": "x"})]),
 ("100222", "securitylog-restriction-removed", "User restriction removed", [slog("user_restriction_removed", {"admin_package": "io.github.erwsim.watchpost", "user_id": 0, "restriction": "no_debugging_features"})]),
 ("100223", "securitylog-media-mounted", "Removable media mounted", [slog("media_mount", {"mount_point": "/storage/ABCD-1234", "label": "USB"})]),
 ("100224", "securitylog-cert-validation", "Certificate validation failure", [slog("cert_validation_failure", {"reason": "untrusted"})]),
 ("100300", "watch-other", "Watcher: unknown finding", [watch({"check": "other", "device_id": "dev_7k2m9q"})]),
 ("100301", "watch-silence", "Silent device", [watch({"check": "silence", "device_id": "dev_7k2m9q", "device_name": "phone", "last_seen": "2026-11-15T20:00:00Z", "silence_min": 95, "threshold_min": 60})]),
 ("100302", "watch-resumed", "Device active again", [watch({"check": "resumed", "device_id": "dev_7k2m9q", "device_name": "phone", "last_seen": "2026-11-15T22:00:00Z"})]),
 ("100303", "watch-sequence-gap", "Unexplained sequence gap", [watch({"check": "seq_gap", "device_id": "dev_7k2m9q", "device_name": "phone", "missing_count": 3, "first_missing": 120, "last_missing": 122, "sample": [120, 121, 122], "explained": "none"})]),
 ("100304", "watch-gap-explained", "Sequence gap caused by the buffer purge", [watch({"check": "seq_gap", "device_id": "dev_7k2m9q", "device_name": "phone", "missing_count": 300, "first_missing": 120, "last_missing": 419, "sample": [120], "explained": "buffer_overflow"})]),
 ("100305", "watch-sequence-reset", "Sequence counter went backwards", [watch({"check": "seq_reset", "device_id": "dev_7k2m9q", "device_name": "phone", "previous_max_seq": 18234, "current_max_seq": 12})]),
 ("100290", "rotation-export", "Export rotated by renaming: no alert", ["ossec: File rotated (inode changed): '/var/watchpost/events.ndjson'."]),
 ("100290", "rotation-adguard", "AdGuard log rotation: no alert", ["ossec: File rotated (inode changed): '/var/adguard/querylog.json'."]),
 ("591", "rotation-other-file", "Rotation of another file: Wazuh rule 591 kept", ["ossec: File rotated (inode changed): '/var/log/autre.log'."]),
 ("100172", "microphone-device-locked", "Microphone used while the device is locked", [ev("sensor.microphone", {"recording": True, "source": "mic", "package": "com.qrscan.free.reader", "silenced": False, "screen_on": False, "locked": True}, 2)]),
 ("100173", "microphone-screen-off-no-call", "Microphone used with the screen off outside a call", [ev("sensor.microphone", {"recording": True, "source": "mic", "package": "com.example.recorder", "silenced": False, "screen_on": False, "locked": False})]),
 ("100170", "microphone-call-screen-off", "Call: screen turned off by the proximity sensor, no alert", [ev("sensor.microphone", {"recording": True, "source": "voice_communication", "package": "com.whatsapp", "silenced": False, "screen_on": False, "locked": False})]),
 ("100174", "camera-device-locked", "Camera used while the device is locked", [ev("sensor.camera", {"camera_id": "1", "in_use": True, "package": "com.qrscan.free.reader", "screen_on": False, "locked": True}, 2)]),
 ("100175", "camera-screen-off", "Camera used with the screen off", [ev("sensor.camera", {"camera_id": "0", "in_use": True, "package": "com.example.app", "screen_on": False, "locked": False})]),
 ("100250", "posture-change-other", "Posture change without severity (return to normal)", [pc("adb_enabled", "true", "false")]),
 ("100251", "posture-change-adb-wifi", "Wireless ADB enabled", [pc("adb_wifi_enabled", "false", "true", 2)]),
 ("100252", "posture-change-adb", "ADB enabled", [pc("adb_enabled", "false", "true", 2)]),
 ("100253", "posture-change-dev-options", "Developer options enabled", [pc("dev_options", "false", "true", 2)]),
 ("100254", "posture-change-unknown-sources", "Unknown sources allowed", [pc("unknown_sources", "false", "true", 2)]),
 ("100255", "posture-change-device-owner", "Device Owner lost", [pc("device_owner", "true", "false", 3)]),
 ("100256", "posture-change-encryption", "Encryption lost", [pc("encrypted", "true", "false", 3)]),
 ("100257", "posture-change-lock", "Secure lock removed", [pc("lock_secure", "true", "false", 3)]),
 ("100258", "posture-change-play-protect", "Play Protect disabled", [pc("play_protect", "true", "false", 2)]),
 ("100259", "posture-change-verified-boot", "Verified boot degraded", [pc("verified_boot_state", "green", "orange", 3)]),
 ("100260", "posture-change-private-dns-auto", "Private DNS switched to automatic", [pc("private_dns_mode", "hostname", "opportunistic", 2)]),
 ("100260", "posture-change-private-dns-off", "Private DNS disabled", [pc("private_dns_mode", "hostname", "off", 2)]),
 ("100261", "posture-change-dns-host", "Private DNS host changed", [pc("private_dns_host", "@@DNS_HOST@@", "dns.adguard-dns.com", 2)]),
 ("100250", "posture-change-dns-host-expected", "Private DNS host restored: no specific alert", [pc("private_dns_host", "", "@@DNS_HOST@@")]),
 ("100264", "posture-change-dns-host-empty", "Private DNS host emptied (marked; the non-strict mode is alerted by 100260)", [pc("private_dns_host", "@@DNS_HOST@@", "")]),
 ("100262", "posture-change-user-ca", "User CA added (marked; the alert is carried by security.ca_cert)", [pc("user_ca_certs", "", H, 2)]),
 ("100265", "posture-change-cas-removed", "User CAs removed (marked; alerted by security.ca_cert)", [pc("user_ca_certs", H, "")]),
 ("100263", "posture-change-patch", "Security patch installed", [pc("security_patch", "2026-10-01", "2026-11-01")]),
 ("100225", "securitylog-boot-orange", "Boot with orange state (marked)", [slog("os_startup", {"verified_boot_state": "orange", "dm_verity_mode": "enforcing"})]),
 ("100226", "securitylog-dm-verity", "dm-verity not enforced", [slog("os_startup", {"verified_boot_state": "green", "dm_verity_mode": "eio"})]),
 ("100210", "securitylog-boot-normal", "Normal boot: no alert", [slog("os_startup", {"verified_boot_state": "green", "dm_verity_mode": "enforcing"})]),
 ("100227", "securitylog-credential-changed", "Lock screen credential changed", [slog("password_changed", {"complexity": 196608, "user_id": 0})]),
 ("100228", "securitylog-key-failure", "Key generation failure", [slog("key_generated", {"success": False, "alias": "watchpost_upload_key", "uid": 10301})]),
 ("100105", "severity-critical-unknown-type", "Unknown type, severity 3", [ev("device.unknown_future_type", {"x": 1}, 3)]),
 ("100106", "severity-warning-unknown-type", "Unknown type, severity 2", [ev("net.unknown_future_type", {"x": 1}, 2)]),
 ("100400", "adguard-query", "DNS query not blocked", [agh("example.org")]),
 ("100401", "adguard-blocked", "DNS query blocked", [agh("app-measurement.com", True, 1)]),
 ("100402", "adguard-threat", "Threat feed domain", [agh("malware.example", True, 30)]),
 ("100403", "adguard-burst", "60 blocked queries in a burst", [agh("ads%d.example" % i, True, 10) for i in range(60)]),
 ("100404", "adguard-threats-repeated", "5 malicious domains", [agh("c2-%d.example" % i, True, 30) for i in range(5)]),
 # --- Remote commands (v1.1, contract §8) and notifications (§10)
 ("100230", "command-issued-ring", "Simple command issued (ring)", [issued("ring", {"duration_s": 60, "vibrate": True})]),
 ("100231", "command-issued-locate", "Remote location requested", [issued("locate")]),
 ("100232", "command-issued-lock", "Remote lock requested (message not exported)", [issued("lock", {}, 1, message_set=True)]),
 ("100233", "command-issued-erase", "Remote erase requested", [issued("wipe", {}, 2)]),
 ("100234", "command-issued-clear-message", "Removal of the lock message requested", [issued("clear_lock_message", {}, 1)]),
 ("100100", "command-issued-imitated", "command.issued sent by a device (without server source): no alert", [ev("command.issued", {"command_id": CMD, "type": "wipe", "signed": True, "created_by": "admin"}, 2)]),
 ("100235", "commands-burst", "8 commands in 10 min to the same device", [issued("lock", {}, 1, message_set=False)] + [issued("ring", {"duration_s": 5}) for _ in range(7)]),
 ("100236", "command-cancelled", "Command cancelled", [ev("command.cancelled", {"command_id": CMD, "type": "ring", "signed": False, "cancelled_by": "admin"}, source="server")]),
 ("100237", "command-expired", "Simple command expired", [ev("command.expired", {"command_id": CMD, "type": "ring", "signed": False, "delivered": False}, 1, source="server")]),
 ("100238", "command-sensitive-expired", "Lock expired without a result", [ev("command.expired", {"command_id": CMD, "type": "lock", "signed": True, "delivered": True}, 1, source="server")]),
 ("100239", "command-result-api", "Result received by the API (marked only)", [ev("command.reported", {"command_id": CMD, "type": "lock", "status": "refused", "detail": "bad_signature", "signed": True, "agent_at": "2026-11-16T10:00:01.000Z"}, 3, source="server")]),
 ("100240", "command-result-simple", "Ring executed", [result("ring", "executed")]),
 ("100241", "command-result-lock", "Lock executed by the phone", [result("lock", "executed", None, 2)]),
 ("100242", "command-result-erase", "Erase executed by the phone", [result("wipe", "executed", None, 2)]),
 ("100243", "command-refused", "Command refused (expired)", [result("lock", "refused", "expired", 1)]),
 ("100244", "command-bad-signature", "Invalid signature (severity 3: no 100105 fallback)", [result("lock", "refused", "bad_signature", 3)]),
 ("100245", "command-channel-locked", "Sensitive command channel locked", [result("wipe", "refused", "locked_out", 3)]),
 ("100246", "command-replayed", "Replay refusal (normal resend)", [result("ring", "refused", "replay", 1)]),
 ("100247", "command-failed", "Command failed", [result("lock", "failed", "not_device_owner", 1)]),
 ("100270", "notification-with-content", "Notification with title and text (never in the description)", [ev("app.notification", {"package": "org.thoughtcrime.securesms", "event": "posted", "category": "msg", "channel": "messages", "ongoing": False, "importance": "high", "title": "Alice <script>\"'", "text": "Your code is 123456 — “secret” \\ line\nnext", "redacted": True})]),
 ("100270", "notification-removed", "Notification removed (without content)", [ev("app.notification", {"package": "com.whatsapp", "event": "removed", "category": "msg", "channel": "c", "ongoing": False, "importance": "default"})]),
 ("100233", "commands-burst-erase", "Burst ending with an erase: the erase alert is not hidden", [issued("ring", {"duration_s": 5}) for _ in range(7)] + [issued("wipe", {}, 2)]),
 # --- v1.2: collector detections (contract §11.3; shapes taken from the real export of the collector)
 ("100460", "detection-threat-domain", "Application that contacts threat domains (sev. 3)", [det("threat_domain", TROJAN, {"blocked": 21, "domain_count": 2, "domains": ["api.secure-bank-sync.example", "gate.cdn-update-check.example"], "lists": ["HaGeZi Threat Intelligence Feeds (medium)"], "requests": 96})]),
 ("100461", "detection-threat-domain-browser", "Browser that followed a phishing link (sev. 2)", [det("threat_domain", BROWSER, {"blocked": 1, "domain_count": 1, "domains": ["login-bank.phish.example"], "lists": ["HaGeZi Threat Intelligence Feeds (medium)"], "requests": 1}, 2)]),
 ("100462", "detection-sms-fraud", "SMS sending by an app that is not the SMS app", [det("sms_abuse", TORCH, {"background": 860, "default_sms_app": ["com.samsung.android.messaging"], "read_contacts": 11, "reason": "not_default_sms_app", "rejected": 0, "sent": 860})]),
 ("100463", "detection-microphone-background", "Microphone and camera in the background (the microphone wins)", [det("sensor_background", SPY, {"camera_background": 3, "camera_count": 3, "microphone_background": 44, "microphone_count": 44, "ops": ["record_audio", "camera"]}, 2)]),
 ("100464", "detection-camera-background", "Camera alone in the background", [det("sensor_background", SPY, {"camera_background": 5, "camera_count": 5, "ops": ["camera"]}, 2)]),
 ("100465", "detection-upload-spike", "Isolated upload spike (sev. 2, moderate level)", [det("upload_spike", VAULT, {"first_hour": "2026-11-16T16:00:00.000Z", "history_hours": 26, "hours": 1, "learning": True, "peak_hour": "2026-11-16T16:00:00.000Z", "screen_on_minutes": 6, "threshold_bytes": 1073741824, "tx_bytes": 3743416320}, 2)]),
 ("100466", "detection-fanout", "Hundreds of addresses in one hour (residential proxy)", [det("fanout", PUZZLE, {"addresses": 476, "connections": 476, "first_hour": "2026-11-16T00:00:00.000Z", "hours": 5, "peak_hour": "2026-11-16T01:00:00.000Z", "ports": [443, 80, 8080], "sample": ["31.15.28.24", "31.19.75.243"], "screen_on_minutes": 0, "threshold": 100}, 2)]),
 ("100467", "detection-mail-ports", "SMTP connection of an ordinary app (sev. 2)", [det("mail_ports", CLEANER, {"addresses": 1, "connections": 2, "ports": [587], "sample": ["64.5.242.51"]}, 2)]),
 ("100468", "detection-spam", "Spam volume (sev. 3)", [det("mail_ports", CLEANER, {"addresses": 347, "connections": 676, "ports": [587, 25], "sample": ["64.5.242.51", "64.36.183.25", "64.37.161.91"]})]),
 ("100469", "detection-dns-bypass", "Public DoH/DoT resolver used", [det("dns_bypass", FASTVPN, {"connections": 70, "providers": ["Cloudflare DNS", "Google Public DNS"], "resolvers": ["1.0.0.1:443", "8.8.8.8:853", "[2606:4700:4700::1111]:443"]}, 2)]),
 ("100470", "detection-new-app-capabilities-severe", "Recent risky app (combo) that obtains SMS sending", [det("new_app_risky", TORCH, newapp(["permission:SEND_SMS"], True, ["sideloaded", "sms_send", "boot_receiver", "combo_sms_fraud"], 91), 3, window=INSTALL_WINDOW)]),
 ("100471", "detection-new-app-capabilities", "Recent app that obtains accessibility (sev. 2)", [det("new_app_risky", ("com.example.helper", "Assistant Plus"), newapp(["accessibility"], False, ["accessibility_service"], 25, level="low"), 2, window=INSTALL_WINDOW)]),
 ("100472", "detection-new-app-vpn", "Recent app that becomes a VPN (sev. 1)", [det("new_app_risky", FASTVPN, newapp(["vpn"], False, ["vpn_service"], 20, level="low"), 1, window=INSTALL_WINDOW)]),
 ("100473", "detection-new-app-risk-only", "High risk without capability: already alerted by app.risk (marked)", [det("new_app_risky", TROJAN, newapp([], True, ["sideloaded", "accessibility_service", "overlay", "combo_banking_trojan"], 95), 3, window=INSTALL_WINDOW)]),
 ("100474", "detection-new-app-risk-only-sev2", "High risk (without combo) without capability (marked)", [det("new_app_risky", ("com.parental.ctrl", "Parental Control"), newapp([], True, ["no_launcher_icon", "background_location", "boot_receiver"], 65), 2, window=INSTALL_WINDOW)]),
 ("100455", "detection-unknown-type", "Detection type without a dedicated rule, sev. 2", [det("future_kind", PUZZLE, {"x": 1}, 2)]),
 ("100454", "detection-unknown-type-sev3", "Detection type without a dedicated rule, sev. 3", [det("future_kind", PUZZLE, {"x": 1}, 3)]),
 ("100450", "detection-unknown-type-sev1", "Detection type without a dedicated rule, sev. 1 (trace)", [det("future_kind", PUZZLE, {"x": 1}, 1)]),
 ("100100", "detection-imitated", "detect.* sent by a device (without server source): no alert", [ev("detect.sms_abuse", {"package": "com.flashlight.pro.tools", "label": "Torch Pro", "evidence": {"sent": 1}}, 3)]),
 ("100451", "detection-update", "Update of an already severe detection (new domain): no second severe alert", [det("threat_domain", TROJAN, {"domains": ["a.example"], "domain_count": 1, "requests": 5, "blocked": 5, "lists": ["TIF"]}), det("threat_domain", TROJAN, {"domains": ["a.example", "b.example"], "domain_count": 2, "requests": 9, "blocked": 9, "lists": ["TIF"]}, update=True)]),
 ("100453", "detection-update-sev2", "Update of a severity 2 detection", [det("fanout", PUZZLE, {"addresses": 320, "ports": [443]}, 2), det("fanout", PUZZLE, {"addresses": 480, "ports": [443, 8080]}, 2, update=True)]),
 ("100452", "detection-escalated", "Severity 2 detection updated to severity 3 (escalation)", [det("mail_ports", CLEANER, {"addresses": 2, "connections": 3, "ports": [587]}, 2), det("mail_ports", CLEANER, {"addresses": 25, "connections": 140, "ports": [587, 25]}, 3, update=True)]),
 ("100489", "detection-correlation", "Two detection types for the same application within 24 h", [det("sms_abuse", TORCH, {"reason": "not_default_sms_app", "sent": 860, "rejected": 0, "background": 860}), det("threat_domain", TORCH, {"domains": ["panel.sms-gateway-pay.example"], "domain_count": 1, "requests": 40, "blocked": 40, "lists": ["TIF"]})]),
 ("100460", "detection-correlation-other-app", "Two detections for two different applications: no correlation", [det("sms_abuse", TORCH, {"reason": "volume", "sent": 300}), det("threat_domain", TROJAN, {"domains": ["c2.example"], "domain_count": 1, "requests": 4, "blocked": 4, "lists": ["TIF"]})]),
 ("100460", "detection-correlation-same-type", "Same type two days in a row: no correlation", [det("threat_domain", TROJAN, {"domains": ["c2.example"], "domain_count": 1}), det("threat_domain", TROJAN, {"domains": ["c2.example"], "domain_count": 1}, window=("2026-11-16T00:00:00.000Z", "2026-11-17T00:00:00.000Z"))]),
 # --- contract §11.4 (lines built from the contract: the collector did not produce them yet)
 ("100475", "detection-sms-permission", "Non-SMS app that holds SEND_SMS (without app.ops)", [det("sms_permission", TORCH, {"permission": "android.permission.SEND_SMS", "default_sms_app": "com.samsung.android.messaging", "installer": "com.google.android.packageinstaller"}, 2)]),
 ("100476", "detection-default-sms-app", "App became the default SMS app (sev. 3)", [det("default_app_changed", TORCH, {"role": "sms", "old": "com.samsung.android.messaging", "new": TORCH[0], "level": "high", "score": 91}, 3)]),
 ("100477", "detection-default-keyboard", "Default keyboard changed (already alerted by app.role: marked)", [det("default_app_changed", ("com.keyboard.themes.free", "Keyboard Themes"), {"role": "keyboard", "old": "com.samsung.android.honeyboard", "new": "com.keyboard.themes.free"}, 2)]),
 ("100481", "detection-inventory-mismatch", "App declared system contradicted by its installer", [det("inventory_mismatch", ("com.android.systemupdate.service", "System Update"), {"installer": "com.google.android.packageinstaller", "contradictions": ["installer:com.google.android.packageinstaller", "app.installed"]})]),
 ("100478", "detection-flood", "More than 200 detections in the day", [ev("detect.flood", {"summary": "limit reached", "window_from": DAY[0], "window_to": DAY[1], "evidence": {"suppressed": 37, "limit": 200}}, 3, source="server")]),
 ("100479", "detection-mute", "Mute of a detection (weakening traced)", [ev("detect.muted", {"type": "detect.dns_bypass", "package": FASTVPN[0], "reason": "DoH wanted", "user": "admin"}, 1, source="server")]),
 ("100480", "detection-unmute", "Mute lifted", [ev("detect.unmuted", {"type": "detect.dns_bypass", "package": FASTVPN[0], "user": "admin"}, 0, source="server")]),
 ("100479", "detection-mute-no-correlation", "Mute after a detection of the same app: no correlation", [det("dns_bypass", FASTVPN, {"connections": 3, "providers": ["Cloudflare DNS"]}, 2), ev("detect.muted", {"type": "detect.dns_bypass", "package": FASTVPN[0], "reason": "DoH wanted", "user": "admin"}, 1, source="server")]),
 ("100456", "detection-recurring", "Recurring detection (sev. capped at 1): trace", [det("mail_ports", ("com.example.reporter", "Reporter"), {"connections": 2, "ports": [587]}, 1, recurring=True)]),
 ("100456", "detection-recurring-no-correlation", "Recurring after another detection of the same app: no correlation", [det("dns_bypass", FASTVPN, {"connections": 3}, 2), det("upload_spike", FASTVPN, {"tx_bytes": 2000000000}, 1, recurring=True)]),
 # --- v1.2: risk profile, roles, operations (§11.2)
 ("100500", "risk-low", "Low risk profile: marked, no alert", [risk(("com.google.android.gms", "Google Play services"), "low", 0, [], "com.android.vending", 254432035)]),
 ("100500", "risk-medium", "Medium risk profile: marked", [risk(("com.qrscan.free.reader", "QR Scanner"), "medium", 35, ["sideloaded", "unknown_installer"], "com.google.android.packageinstaller")]),
 ("100501", "risk-high-outside-installation", "High risk without a recent installation (update)", [risk(("com.parental.ctrl", "Parental Control"), "high", 65, ["no_launcher_icon", "background_location", "boot_receiver"], "com.android.vending")]),
 ("100502", "risk-high-installation", "High-risk application installed", [ev("app.installed", {"package": "com.parental.ctrl", "version_name": "3.1", "version_code": 31, "installer": "com.android.vending", "signer_sha256": H}), risk(("com.parental.ctrl", "Parental Control"), "high", 65, ["no_launcher_icon", "background_location", "boot_receiver"], "com.android.vending")]),
 ("100503", "risk-combo-installation", "Application with a malware profile installed", [ev("app.installed", {"package": TORCH[0], "version_name": "1.0", "version_code": 7, "installer": "com.google.android.packageinstaller", "signer_sha256": H}, 1), risk(TORCH, "high", 91, ["sideloaded", "unknown_installer", "no_launcher_icon", "sms_send", "boot_receiver", "combo_sms_fraud"], "com.google.android.packageinstaller")]),
 ("100501", "risk-high-other-installation", "Installation of another application: no correlation", [ev("app.installed", {"package": "org.example.app", "version_name": "1", "version_code": 1, "installer": "com.android.vending", "signer_sha256": H}), risk(("com.parental.ctrl", "Parental Control"), "high", 65, ["boot_receiver"], "com.android.vending")]),
 ("100511", "role-sms", "New default SMS app", [ev("app.role", {"role": "sms", "old": "com.samsung.android.messaging", "new": TORCH[0]}, 2)]),
 ("100512", "role-dialer", "New default phone app", [ev("app.role", {"role": "dialer", "old": "com.samsung.android.dialer", "new": "com.truecaller"}, 2)]),
 ("100513", "role-keyboard", "New default keyboard", [ev("app.role", {"role": "keyboard", "old": "com.samsung.android.honeyboard", "new": "com.keyboard.themes.free"}, 2)]),
 ("100514", "role-assistant", "New default assistant", [ev("app.role", {"role": "assistant", "old": "com.google.android.googlequicksearchbox", "new": "com.example.assistant"}, 2)]),
 ("100510", "role-browser", "New default browser (information)", [ev("app.role", {"role": "browser", "old": "com.sec.android.app.sbrowser", "new": "org.mozilla.firefox"}, 1)]),
 ("100510", "role-sms-unknown", "SMS role became unreadable (new missing): information", [ev("app.role", {"role": "sms", "old": "com.samsung.android.messaging"}, 2)]),
 ("100520", "operations-app", "Ordinary app.ops.app: marked", [ev("app.ops.app", {"background_count": 3, "count": 8, "from": "2026-11-13T17:00:00Z", "last_ts": "2026-11-13T17:33:32.227Z", "op": "fine_location", "package": "com.google.android.gms", "rejected_count": 0, "to": "2026-11-13T18:00:00Z"})]),
 ("100522", "operations-sms-refused", "SMS sending refused (SMS guard)", [ev("app.ops.app", {"background_count": 0, "count": 0, "from": "2026-11-16T13:00:00Z", "last_ts": "2026-11-16T13:16:20.276Z", "op": "send_sms", "package": TORCH[0], "rejected_count": 76, "to": "2026-11-16T14:00:00Z"})]),
 ("100521", "operations-call-refused", "Call refused (call guard)", [ev("app.ops.app", {"background_count": 2, "count": 0, "from": "2026-11-16T13:00:00Z", "op": "call_phone", "package": "com.example.dialer.fraud", "rejected_count": 2, "to": "2026-11-16T14:00:00Z"})]),
 ("100161", "permission-send-sms", "SMS sending permission granted (defence in depth, without app.ops)", [ev("app.permission_changed", {"package": TORCH[0], "permission": "android.permission.SEND_SMS", "granted": True}, 1)]),
 # --- v1.2: guards (security.policy, profile guard:<key>, §11.1)
 ("100531", "guard-enabled", "SMS guard enabled", [guard("guard_enabled", "sms", "sms")]),
 ("100532", "guard-disabled", "SMS guard disabled (weakening)", [guard("guard_disabled", "sms", "sms")]),
 ("100533", "guard-quarantine", "Application quarantined", [guard("quarantined", "quarantine", TORCH[0])]),
 ("100534", "guard-released", "Application released from quarantine", [guard("released", "quarantine", TORCH[0])]),
 ("100530", "guard-permission-denied", "Permission denied by a guard: marked", [guard("permission_denied", "sms", TORCH[0], "android.permission.SEND_SMS", 1)]),
 ("100535", "guard-permission-restored", "Permission restored by a guard", [guard("permission_restored", "sms", "com.example.otp", "android.permission.SEND_SMS")]),
 ("100187", "guard-failure", "Failure of a guard on a package (ok = false, failure alert)", [guard("permission_denied", "sms", "com.example.app", "android.permission.SEND_SMS", 1, ok=False)]),
 # --- v1.2: Tracking page (tracking.*, collector events)
 ("100540", "tracking-level-strengthened", "Blocking level strengthened (sev. 1)", [ev("tracking.level_changed", {"old": "balanced", "new": "strict", "changes": 4, "user": "admin"}, 1, source="server")]),
 ("100541", "tracking-level-weakened", "Blocking level lowered (sev. 2)", [ev("tracking.level_changed", {"old": "strict", "new": "permissive", "changes": 5, "user": "admin"}, 2, source="server")]),
 ("100546", "tracking-level-from-unknown", "Level set from an unknown state (old missing, sev. 2)", [ev("tracking.level_changed", {"new": "balanced", "changes": 2, "user": "admin"}, 2, source="server")]),
 ("100100", "tracking-level-imitated", "tracking.* sent by a device: no alert", [ev("tracking.level_changed", {"old": "strict", "new": "permissive", "user": "admin"}, 2)]),
 ("100542", "tracking-block", "Domain blocked from the console", [ev("tracking.override", {"domain": "graph.facebook.com", "action": "block", "forced": False, "user": "admin"}, 1, source="server")]),
 ("100543", "tracking-allow", "Domain force-allowed from the console", [ev("tracking.override", {"domain": "gate.cdn-update-check.example", "action": "allow", "forced": False, "user": "admin"}, 2, source="server")]),
 ("100544", "tracking-block-removed", "Manual block removed", [ev("tracking.override", {"domain": "graph.facebook.com", "action": "default", "forced": False, "previous": "block", "user": "admin"}, 2, source="server")]),
 ("100545", "tracking-block-essential", "Forced block of an essential domain", [ev("tracking.override", {"domain": "fcm.googleapis.com", "action": "block", "forced": True, "user": "admin"}, 2, source="server")]),
 ("100542", "tracking-allow-removed", "Allow removed (back to default, strengthening)", [ev("tracking.override", {"domain": "x.example", "action": "default", "forced": False, "previous": "allow", "user": "admin"}, 1, source="server")]),
]
for i, (rid, slug, desc, lines) in enumerate(cases, 1):
    with open(os.path.join(out, "%03d-%s.log" % (i, slug)), "w") as f:
        f.write("# %s\n# expected: %s\n" % (desc, rid))
        for l in lines:
            f.write(l.replace('"private_dns_host":null,', '') + "\n")
print(len(cases), "cases")
