package sim

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
)

const securityPatch = "2026-10-01"

func basePosture(t time.Time, dnsHost string) map[string]any {
	patch, _ := time.Parse("2006-01-02", securityPatch)
	return map[string]any{
		"security_patch": securityPatch, "patch_age_days": int(t.Sub(patch).Hours() / 24), "encrypted": true,
		"lock_secure": true, "adb_enabled": false, "adb_wifi_enabled": false, "dev_options": false, "unknown_sources": false,
		"private_dns_mode": "hostname", "private_dns_host": dnsHost, "always_on_vpn": false, "device_owner": true,
		"verified_boot_state": "green", "user_ca_certs": []any{}, "play_protect": true, "usb_data_signaling": true,
	}
}

func (g *Generator) postureEvent(t time.Time, sev int) {
	patch, _ := time.Parse("2006-01-02", securityPatch)
	g.posture["patch_age_days"] = int(t.Sub(patch).Hours() / 24)
	cp := make(map[string]any, len(g.posture))
	for k, v := range g.posture {
		cp[k] = v
	}
	g.emit(t, "security.posture", sev, cp)
	g.postureChanges(t.Add(time.Millisecond), cp)
}

// postureChanges emits one security.posture_change per field that differs from the previous
// security.posture (contract §2, catalog details), values converted to strings. patch_age_days
// is derived from the date and is not a change of the device.
func (g *Generator) postureChanges(t time.Time, cur map[string]any) {
	now := make(map[string]string, len(cur))
	for k, v := range cur {
		now[k] = postureString(v)
	}
	prev := g.postureSnt
	g.postureSnt = now
	if prev == nil {
		return
	}
	keys := make([]string, 0, len(now))
	for k := range now {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "patch_age_days" || prev[k] == now[k] {
			continue
		}
		g.emit(t, "security.posture_change", postureChangeSev(k, now[k]), map[string]any{"field": k, "old": prev[k], "new": now[k]})
		t = t.Add(time.Millisecond)
	}
}

func postureString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = postureString(e)
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(x)
	}
}

// postureChangeSev: severity hint of a posture change, as the agent would set it.
func postureChangeSev(field, val string) int {
	switch field {
	case "device_owner", "encrypted", "lock_secure":
		if val == "false" {
			return 3
		}
	case "verified_boot_state":
		if val != "green" {
			return 3
		}
	case "adb_enabled", "adb_wifi_enabled", "dev_options", "unknown_sources":
		if val == "true" {
			return 2
		}
	case "play_protect":
		if val == "false" {
			return 2
		}
	case "private_dns_mode", "private_dns_host":
		return 2
	case "user_ca_certs":
		if val != "" {
			return 2
		}
	}
	return 0
}

// startup emits what the agent reports when its service starts.
func (g *Generator) startup(t time.Time, reason string) {
	g.emit(t, "agent.started", 0, map[string]any{"reason": reason, "agent_version": g.version})
	for i, p := range []map[string]any{
		{"action": "private_dns_set", "target": g.dnsHost, "profile": "equilibre", "ok": true},
		{"action": "network_logging", "target": "enabled", "profile": "equilibre", "ok": true},
		{"action": "security_logging", "target": "enabled", "profile": "equilibre", "ok": true},
		{"action": "restriction_set", "target": "no_install_unknown_sources_globally", "profile": "equilibre", "ok": true},
		{"action": "package_disabled", "target": "com.facebook.appmanager", "profile": "equilibre", "ok": true},
		{"action": "package_disabled", "target": "com.facebook.services", "profile": "equilibre", "ok": true},
		{"action": "package_disabled", "target": "com.samsung.android.app.tips", "profile": "equilibre", "ok": true},
		{"action": "package_disabled", "target": "com.samsung.android.da.daagent", "profile": "equilibre", "ok": false,
			"error": "SecurityException: package is required by the system"},
	} {
		sev := 0
		if p["ok"] == false {
			sev = 1
		}
		g.emit(t.Add(time.Duration(200+i*150)*time.Millisecond), "security.policy", sev, p)
	}
	seg, _ := segmentAt(t.In(g.loc))
	g.connectivity(t.Add(2*time.Second), placeWifi(seg.place))
	if w := placeWifi(seg.place); w != nil {
		g.emit(t.Add(2100*time.Millisecond), "net.wifi", 0, map[string]any{"event": "connected", "ssid": w.ssid, "bssid": w.bssid,
			"rssi": -52, "freq_mhz": w.freq, "security": w.security, "standard": w.standard})
	}
	g.cellChange(t.Add(2200 * time.Millisecond))
	g.emit(t.Add(2300*time.Millisecond), "net.bluetooth", 0, map[string]any{"event": "state", "enabled": true})
	g.emit(t.Add(2400*time.Millisecond), "net.nfc", 0, map[string]any{"enabled": true})
	g.emit(t.Add(2500*time.Millisecond), "net.hotspot", 0, map[string]any{"enabled": false})
	g.emit(t.Add(2600*time.Millisecond), "location.provider", 0, map[string]any{"provider": "gps", "enabled": true})
	g.emit(t.Add(2700*time.Millisecond), "device.airplane_mode", 0, map[string]any{"enabled": false})
	g.emit(t.Add(2800*time.Millisecond), "device.thermal", 0, map[string]any{"status": "none"})
	g.emit(t.Add(2900*time.Millisecond), "device.battery", 0, map[string]any{"pct": int(g.battery), "plugged": g.plugged,
		"status": "discharging", "temperature_c": 29.5, "health": "good"})
	g.daily(t.Add(3*time.Second), false)
}

// daily emits the inventories and the posture (daily job, and at start-up).
func (g *Generator) daily(t time.Time, updates bool) {
	g.emit(t, "device.inventory", 0, map[string]any{
		"manufacturer": "samsung", "model": "SM-S936B", "android_release": "16", "sdk_int": 36, "security_patch": securityPatch,
		"build_fingerprint": "samsung/pa3qxeea/pa3q:16/BP2A.250605.031.A3/S936BXXU4BYJ5:user/release-keys",
		"one_ui":            "8.0", "kernel": "6.6.77-android16-11-gS936BXXU4BYJ5-abS936BXXU4BYJ5", "bootloader": "S936BXXU4BYJ5",
		"verified_boot_state": "green", "total_storage_bytes": int64(256e9), "total_ram_bytes": int64(12e9),
	})
	g.emit(t.Add(500*time.Millisecond), "device.storage", 0, map[string]any{
		"free_bytes": int64(118e9) - int64(g.rng.Intn(4e9)), "total_bytes": int64(256e9)})
	if updates {
		for i := 0; i < 1+g.rng.Intn(3); i++ {
			a := &apps[g.rng.Intn(len(apps))]
			if a.installer != "com.android.vending" {
				continue
			}
			a.code++
			ut := t.Add(time.Duration(5+g.rng.Intn(600)) * time.Second)
			g.emit(ut, "app.updated", 0, map[string]any{
				"package": a.pkg, "version_name": a.version, "version_code": a.code, "installer": a.installer, "signer_sha256": sha256Hex("signer:" + a.pkg)})
			g.riskFor(ut, riskOf(a)) // the agent scores an application at each update
		}
	}
	// Inventory split into parts, all carrying the same inventory_id (contract §2).
	// The identifier has its own random source so that adding it did not change
	// the rest of a seeded simulation.
	const perPart = 11
	inventoryID := NewULID(t, rand.New(rand.NewSource(g.seed^t.UnixNano())))
	var entries []any
	for _, a := range apps {
		first := time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC).Add(time.Duration(hash64(a.pkg)%(150*24)) * time.Hour)
		if a.system {
			first = time.Date(2026, 3, 1, 9, 12, 0, 0, time.UTC)
		}
		dang := make([]any, len(a.dangerous))
		for i, d := range a.dangerous {
			dang[i] = d
		}
		entries = append(entries, map[string]any{
			"package": a.pkg, "label": a.label, "version_name": a.version, "version_code": a.code, "installer": a.installer,
			"system": a.system, "enabled": true, "suspended": false, "hidden": false, "target_sdk": a.target,
			"first_install": first.Format(time.RFC3339), "last_update": t.Add(-time.Duration(hash64(a.pkg+"u")%(40*24)) * time.Hour).Format(time.RFC3339),
			"signer_sha256": sha256Hex("signer:" + a.pkg), "granted_dangerous": dang,
		})
	}
	entries = append(entries, g.attackInventory(t)...) // applications installed by the attack scenarios
	parts := (len(entries) + perPart - 1) / perPart
	for p := range parts {
		list := entries[p*perPart : min(len(entries), (p+1)*perPart)]
		g.emit(t.Add(time.Duration(1000+p*20)*time.Millisecond), "app.inventory", 0, map[string]any{"inventory_id": inventoryID, "part": p + 1, "parts": parts, "apps": list})
	}
	g.emit(t.Add(1500*time.Millisecond), "app.special_access", 0, map[string]any{
		"accessibility_services": []any{},
		"notification_listeners": []any{"io.github.erwsim.watchpost/io.github.erwsim.watchpost.collect.NotificationCollector", "com.samsung.android.app.watchmanager/.NotificationListener"},
		"device_admins":          []any{"io.github.erwsim.watchpost/.admin.WatchpostAdminReceiver", "com.google.android.gms/.mdm.receivers.MdmDeviceAdminReceiver"},
		"overlay_apps":           []any{"com.samsung.android.app.cocktailbarservice"},
		"unknown_sources_apps":   []any{},
		"usage_access_apps":      []any{"io.github.erwsim.watchpost", "com.google.android.gms", "com.samsung.android.lool"},
		"vpn_apps":               []any{},
		"default_apps": map[string]any{"browser": "com.android.chrome", "sms": "com.samsung.android.messaging",
			"dialer": "com.samsung.android.dialer", "home": "com.sec.android.app.launcher", "assistant": "com.google.android.googlequicksearchbox"},
	})
	g.postureEvent(t.Add(1600*time.Millisecond), 0)
}

// PlanScenario places the rare and severe events of the catalog between from
// and to, so that every type of contract §2 appears at least once.
func (g *Generator) PlanScenario(from, to time.Time) {
	span := to.Sub(from)
	if span < 30*time.Minute {
		span = 30 * time.Minute
	}
	at := func(f float64) time.Time {
		return from.Add(time.Duration(f * float64(span))).Add(time.Duration(g.rng.Intn(30)) * time.Second)
	}

	// Reboot for a "system update" at the first 04:10 local in the window, else at 10 %.
	rb := at(0.1)
	for d := from.In(g.loc); d.Before(to); d = d.Add(time.Hour) {
		c := time.Date(d.Year(), d.Month(), d.Day(), 4, 10, 0, 0, g.loc).UTC()
		if c.After(from) && c.Before(to.Add(-5*time.Minute)) {
			rb = c
			break
		}
	}
	g.reboot(rb)

	g.bleTracker(at(0.33))
	g.emit(at(0.36), "net.cell_security", 2, map[string]any{"kind": "downgrade_2g", "detail": "Bascule forcée en GSM (2G), chiffrement A5/1 annoncé par la cellule"})
	g.emit(at(0.37), "net.cell_security", 3, map[string]any{"kind": "null_cipher", "detail": "Cellule 208-01 sans chiffrement (A5/0) pendant 40 s"})

	ca := at(0.45)
	caSHA := sha256Hex("corporate-proxy-ca")
	g.emit(ca, "security.ca_cert", 2, map[string]any{"event": "added", "sha256": caSHA, "subject": "CN=Corporate Proxy Root CA, O=Example Corp"})
	g.emit(ca.Add(time.Second), "security.log", 1, map[string]any{"tag": "cert_authority_installed", "level": "info",
		"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"success": true, "subject": "CN=Corporate Proxy Root CA, O=Example Corp", "user_id": 0}})
	// State changes go through later() so that every posture in between stays consistent.
	g.later(ca.Add(2*time.Second), func(t time.Time) {
		g.posture["user_ca_certs"] = []any{caSHA}
		g.postureEvent(t, 1)
	})
	g.emit(ca.Add(3*time.Hour), "security.ca_cert", 2, map[string]any{"event": "removed", "sha256": caSHA, "subject": "CN=Corporate Proxy Root CA, O=Example Corp"})
	g.emit(ca.Add(3*time.Hour+500*time.Millisecond), "security.log", 0, map[string]any{"tag": "cert_authority_removed", "level": "info",
		"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"success": true, "subject": "CN=Corporate Proxy Root CA, O=Example Corp", "user_id": 0}})
	g.later(ca.Add(3*time.Hour+time.Second), func(t time.Time) {
		g.posture["user_ca_certs"] = []any{}
		g.postureEvent(t, 0)
	})

	tam := at(0.52)
	g.emit(tam, "agent.tamper", 3, map[string]any{"kind": "permission_revoked", "detail": "android.permission.ACCESS_FINE_LOCATION retirée à Watchpost"})
	g.emit(tam.Add(90*time.Second), "agent.tamper", 3, map[string]any{"kind": "force_stop", "detail": "arrêt forcé du service détecté au redémarrage"})
	g.emit(at(0.15), "agent.collector_error", 1, map[string]any{"collector": "wifi_scan", "error": "SecurityException: startScan limité (4 balayages / 2 min)"})
	g.emit(at(0.2), "agent.config_changed", 0, map[string]any{"key": "upload.wifi_only", "old": false, "new": true})
	g.emit(at(0.21), "agent.config_changed", 0, map[string]any{"key": "upload.wifi_only", "old": true, "new": false})
	ov := at(0.6)
	g.later(ov, func(t time.Time) {
		g.dropped += 120
		g.emit(t, "agent.buffer_overflow", 1, map[string]any{"dropped": 120,
			"oldest_ts": t.Add(-31 * 24 * time.Hour).Format("2006-01-02T15:04:05.000Z07:00"),
			"newest_ts": t.Add(-29 * 24 * time.Hour).Format("2006-01-02T15:04:05.000Z07:00")})
	})

	tc := at(0.25)
	g.emit(tc, "device.time_changed", 0, map[string]any{"delta_ms": -1834})
	g.emit(tc.Add(time.Minute), "device.timezone_changed", 0, map[string]any{"tz": "Europe/Paris"})

	usb := at(0.7)
	g.emit(usb, "device.usb", 0, map[string]any{"connected": true, "configured": true, "functions": []any{"mtp"}})
	g.emit(usb.Add(12*time.Minute), "device.usb", 0, map[string]any{"connected": false, "configured": false, "functions": []any{}})
	usbKey := at(0.72)
	g.emit(usbKey, "device.usb", 1, map[string]any{"connected": true, "configured": true, "functions": []any{"host"},
		"device": map[string]any{"vendor_id": 1921, "product_id": 21889, "manufacturer": "SanDisk", "product": "Ultra USB 3.0", "class": "mass_storage"}})
	g.emit(usbKey.Add(4*time.Minute), "device.usb", 0, map[string]any{"connected": false, "configured": false, "functions": []any{}})

	air := at(0.8)
	g.emit(air, "device.airplane_mode", 0, map[string]any{"enabled": true})
	g.emit(air.Add(18*time.Minute), "device.airplane_mode", 0, map[string]any{"enabled": false})
	gps := at(0.4)
	g.emit(gps, "location.provider", 1, map[string]any{"provider": "gps", "enabled": false})
	g.emit(gps.Add(9*time.Minute), "location.provider", 0, map[string]any{"provider": "gps", "enabled": true})
	hs := at(0.85)
	g.emit(hs, "net.hotspot", 0, map[string]any{"enabled": true})
	g.emit(hs.Add(25*time.Minute), "net.hotspot", 0, map[string]any{"enabled": false})
	g.emit(at(0.86), "net.nfc", 0, map[string]any{"enabled": false})
	g.emit(at(0.87), "net.nfc", 0, map[string]any{"enabled": true})
	ps := at(0.62)
	g.emit(ps, "device.power_save", 0, map[string]any{"enabled": true})
	g.emit(ps.Add(40*time.Minute), "device.power_save", 0, map[string]any{"enabled": false})
	th := at(0.55)
	g.emit(th, "device.thermal", 1, map[string]any{"status": "moderate"})
	g.emit(th.Add(20*time.Minute), "device.thermal", 0, map[string]any{"status": "none"})

	inst := at(0.3)
	g.emit(inst, "app.installed", 0, map[string]any{"package": "fr.vinted", "version_name": "25.44.0", "version_code": 254400,
		"installer": "com.android.vending", "signer_sha256": sha256Hex("signer:fr.vinted")})
	g.riskFor(inst, riskOf(&app{pkg: "fr.vinted", label: "Vinted", installer: "com.android.vending", code: 254400, target: 35}))
	g.emit(inst.Add(3*time.Minute), "app.permission_changed", 0, map[string]any{"package": "fr.vinted", "permission": "android.permission.CAMERA", "granted": true})
	g.emit(inst.Add(4*time.Minute), "app.permission_changed", 0, map[string]any{"package": "com.instagram.android", "permission": "android.permission.ACCESS_FINE_LOCATION", "granted": false})
	side := at(0.66)
	g.emit(side, "app.installed", 2, map[string]any{"package": "com.qrscan.free.reader", "version_name": "3.1.7", "version_code": 317,
		"installer": "com.google.android.packageinstaller", "signer_sha256": sha256Hex("signer:qrscan")})
	g.riskFor(side, riskOf(&app{pkg: "com.qrscan.free.reader", label: "QR Scanner", installer: "com.google.android.packageinstaller", code: 317, target: 33}))
	g.emit(side.Add(26*time.Minute), "app.removed", 0, map[string]any{"package": "com.qrscan.free.reader", "version_name": "3.1.7", "version_code": 317,
		"installer": "com.google.android.packageinstaller", "signer_sha256": sha256Hex("signer:qrscan")})

	kg := at(0.5)
	for i := 1; i <= 3; i++ {
		sev := 1
		if i >= 3 {
			sev = 2
		}
		ts := kg.Add(time.Duration(i*6) * time.Second)
		g.emit(ts, "security.keyguard", sev, map[string]any{"event": "unlock_failed", "failed_attempts": i})
		g.emit(ts.Add(10*time.Millisecond), "security.log", 1, map[string]any{"tag": "keyguard_dismiss_auth_attempt", "level": "warning",
			"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"success": false, "strength": 1}})
	}
	g.emit(kg.Add(40*time.Second), "security.keyguard", 0, map[string]any{"event": "unlock_succeeded", "failed_attempts": 3})

	// Sensors carry the screen state (contract §2, catalog details): screen_on, locked.
	sensor := func(ts time.Time, typ string, sev int, d map[string]any, screenOn, locked bool) {
		d["screen_on"], d["locked"] = screenOn, locked
		g.emit(ts, typ, sev, d)
	}
	cam := at(0.42)
	sensor(cam, "sensor.camera", 0, map[string]any{"camera_id": "0", "in_use": true, "package": "com.sec.android.app.camera"}, true, false)
	sensor(cam.Add(35*time.Second), "sensor.camera", 0, map[string]any{"camera_id": "0", "in_use": false, "package": "com.sec.android.app.camera"}, true, false)
	// A call: the proximity sensor turns the screen off, the phone is not locked.
	call := at(0.75)
	sensor(call, "sensor.microphone", 0, map[string]any{"recording": true, "source": "voice_communication", "package": "com.whatsapp", "silenced": false}, false, false)
	sensor(call.Add(7*time.Minute), "sensor.microphone", 0, map[string]any{"recording": false, "source": "voice_communication", "package": "com.whatsapp", "silenced": false}, true, false)
	sensor(at(0.77), "sensor.camera", 1, map[string]any{"camera_id": "1", "in_use": true, "package": "com.instagram.android"}, true, false)
	sensor(at(0.77).Add(50*time.Second), "sensor.camera", 0, map[string]any{"camera_id": "1", "in_use": false, "package": "com.instagram.android"}, true, false)
	// Suspicious: the sideloaded app records and films while the phone is locked, screen off.
	spy := at(0.67)
	sensor(spy, "sensor.microphone", 2, map[string]any{"recording": true, "source": "mic", "package": "com.qrscan.free.reader", "silenced": false}, false, true)
	sensor(spy.Add(2*time.Minute), "sensor.microphone", 0, map[string]any{"recording": false, "source": "mic", "package": "com.qrscan.free.reader", "silenced": false}, false, true)
	sensor(spy.Add(3*time.Minute), "sensor.camera", 2, map[string]any{"camera_id": "1", "in_use": true, "package": "com.qrscan.free.reader"}, false, true)
	sensor(spy.Add(3*time.Minute+20*time.Second), "sensor.camera", 0, map[string]any{"camera_id": "1", "in_use": false, "package": "com.qrscan.free.reader"}, false, true)

	// security.log with the payload names of the contract table.
	g.emit(side.Add(200*time.Millisecond), "security.log", 0, map[string]any{"tag": "package_installed", "level": "info",
		"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"package": "com.qrscan.free.reader", "version_code": 317, "user_id": 0}})
	g.emit(usbKey.Add(2*time.Second), "security.log", 0, map[string]any{"tag": "media_mount", "level": "info",
		"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"mount_point": "/storage/4A21-0000", "label": "SanDisk"}})
	g.emit(usbKey.Add(4*time.Minute), "security.log", 0, map[string]any{"tag": "media_unmount", "level": "info",
		"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"mount_point": "/storage/4A21-0000", "label": "SanDisk"}})

	// Temporary posture degradations (one security.posture_change per field).
	g.later(at(0.92), func(t time.Time) {
		g.posture["unknown_sources"] = true
		g.posture["play_protect"] = false
		g.postureEvent(t, 2)
	})
	g.later(at(0.92).Add(20*time.Minute), func(t time.Time) {
		g.posture["unknown_sources"] = false
		g.posture["play_protect"] = true
		g.postureEvent(t, 0)
	})
	g.later(at(0.95), func(t time.Time) {
		g.posture["private_dns_mode"] = "opportunistic"
		g.posture["private_dns_host"] = ""
		g.postureEvent(t, 2)
	})
	g.later(at(0.95).Add(10*time.Minute), func(t time.Time) {
		g.posture["private_dns_mode"] = "hostname"
		g.posture["private_dns_host"] = g.dnsHost
		g.postureEvent(t, 0)
	})

	dev := at(0.9)
	g.later(dev, func(t time.Time) {
		g.posture["dev_options"] = true
		g.posture["adb_enabled"] = true
		g.postureEvent(t, 2)
		g.emit(t.Add(2*time.Minute), "security.log", 1, map[string]any{"tag": "adb_shell_interactive", "level": "info",
			"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{}})
		g.emit(t.Add(3*time.Minute), "security.log", 1, map[string]any{"tag": "adb_shell_cmd", "level": "info",
			"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"command": "pm list packages -3"}})
		g.emit(t.Add(4*time.Minute), "security.log", 1, map[string]any{"tag": "sync_recv_file", "level": "info",
			"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"path": "/sdcard/Download/rapport.pdf"}})
	})
	g.later(dev.Add(90*time.Minute), func(t time.Time) {
		g.posture["dev_options"] = false
		g.posture["adb_enabled"] = false
		g.postureEvent(t, 0)
	})
	g.mockFixAt = at(0.58)
}

// later runs fn when generation reaches t (state changes that must happen in order).
func (g *Generator) later(t time.Time, fn func(time.Time)) {
	g.laters = append(g.laters, laterFn{at: t.UTC().Truncate(time.Millisecond), fn: fn})
	sort.SliceStable(g.laters, func(i, j int) bool { return g.laters[i].at.Before(g.laters[j].at) })
}

type laterFn struct {
	at time.Time
	fn func(time.Time)
}

func (g *Generator) reboot(t time.Time) {
	g.emit(t, "agent.stopped", 0, map[string]any{"reason": "shutdown", "agent_version": g.version})
	g.emit(t.Add(time.Second), "device.shutdown", 0, map[string]any{"reason": "reboot"})
	g.emit(t.Add(1500*time.Millisecond), "security.log", 0, map[string]any{"tag": "os_shutdown", "level": "info", "log_id": g.rng.Intn(1 << 20), "fields": map[string]any{}})
	up := t.Add(85 * time.Second)
	g.boots = append(g.boots, boot{at: up.Add(-20 * time.Second), id: g.newBootID()})
	// Logs recovered from before the reboot (the agent reads the log buffer persisted by the system):
	// their ts predates the shutdown.
	for i, tag := range []string{"wifi_disconnection", "keyguard_secured"} {
		fields := map[string]any{}
		if tag == "wifi_disconnection" {
			fields = map[string]any{"bssid": wifiHome.bssid, "reason": "leaving"}
		}
		g.emitExtra(t.Add(-time.Duration(30*(i+1))*time.Second), "security.log", 0, map[string]any{"tag": tag, "level": "info",
			"log_id": g.xrng.Intn(1 << 20), "fields": fields, "pre_reboot": true})
	}
	g.emit(up, "device.boot", 0, map[string]any{"reason": "reboot"})
	g.emit(up.Add(200*time.Millisecond), "security.log", 0, map[string]any{"tag": "os_startup", "level": "info", "log_id": g.rng.Intn(1 << 20),
		"fields": map[string]any{"verified_boot_state": "green", "dm_verity_mode": "enforcing"}})
	g.emit(up.Add(300*time.Millisecond), "security.log", 0, map[string]any{"tag": "logging_started", "level": "info", "log_id": g.rng.Intn(1 << 20), "fields": map[string]any{}})
	g.emit(up.Add(400*time.Millisecond), "security.log", 0, map[string]any{"tag": "key_generated", "level": "info", "log_id": g.rng.Intn(1 << 20),
		"fields": map[string]any{"success": true, "alias": "watchpost_upload_key", "uid": 10301}})
	g.emit(up.Add(time.Second), "agent.started", 0, map[string]any{"reason": "boot_completed", "agent_version": g.version})
}

func (g *Generator) bleTracker(t time.Time) {
	addr := "d2:6a:91:3c:7e:05"
	first := t.Add(-35 * time.Minute)
	for i, s := range []int{3, 6, 11} {
		g.emit(t.Add(time.Duration(i*20)*time.Minute), "net.ble_tracker", 2, map[string]any{"address": addr, "kind": "airtag",
			"rssi": -60 - 5*i, "first_seen": first.Format("2006-01-02T15:04:05.000Z07:00"), "sightings": s})
	}
	g.emit(t.Add(5*time.Minute), "net.ble_tracker", 2, map[string]any{"address": "e1:44:0b:9a:27:c3", "kind": "smarttag",
		"rssi": -82, "first_seen": t.Add(-12 * time.Minute).Format("2006-01-02T15:04:05.000Z07:00"), "sightings": 3})
}
