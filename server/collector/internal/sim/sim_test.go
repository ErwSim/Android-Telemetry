package sim

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
)

// catalog is the list of types of contract §2.
var catalog = []string{
	"agent.started", "agent.stopped", "agent.heartbeat", "agent.buffer_overflow", "agent.collector_error", "agent.config_changed", "agent.tamper",
	"device.inventory", "device.boot", "device.shutdown", "device.screen", "device.battery", "device.power_save", "device.storage",
	"device.thermal", "device.time_changed", "device.timezone_changed", "device.usb", "device.airplane_mode",
	"location.fix", "location.provider",
	"net.connectivity", "net.wifi", "net.wifi_scan", "net.cell", "net.cell_security", "net.dns", "net.connect", "net.usage",
	"net.bluetooth", "net.ble_tracker", "net.hotspot", "net.nfc",
	"app.inventory", "app.installed", "app.updated", "app.removed", "app.foreground", "app.permission_changed", "app.special_access", "app.notification",
	"sensor.camera", "sensor.microphone",
	"security.log", "security.posture", "security.posture_change", "security.keyguard", "security.ca_cert", "security.policy",
}

func generate(t *testing.T, start time.Time, span time.Duration) []Event {
	t.Helper()
	return generateOpts(t, Options{Start: start, Seed: 42, Rate: 1, SeqBase: 1000}, span)
}

func generateOpts(t *testing.T, opts Options, span time.Duration) []Event {
	t.Helper()
	start := opts.Start
	g := New(opts)
	end := start.Add(span)
	g.PlanScenario(start, end)
	var all []Event
	for ts := start; ts.Before(end); ts = ts.Add(time.Hour) {
		all = append(all, g.Advance(ts.Add(time.Hour))...)
	}
	return all
}

func TestCoverageAndValidity(t *testing.T) {
	// A weekday, to include the commute.
	start := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	evs := generate(t, start, 24*time.Hour)
	counts := map[string]int{}
	ids := map[string]bool{}
	var prevSeq int64
	var prevTS time.Time
	sev := map[int]int{}
	now := start.Add(25 * time.Hour)
	for _, e := range evs {
		counts[e.Type]++
		sev[e.Sev]++
		raw, _ := json.Marshal(e)
		pe, err := model.ParseEvent(raw, now)
		if err != nil {
			t.Fatalf("invalid generated event %s: %v", raw, err)
		}
		if ids[pe.ID] {
			t.Fatalf("duplicate id %s", pe.ID)
		}
		ids[pe.ID] = true
		if e.Seq <= prevSeq {
			t.Fatalf("seq not increasing: %d after %d", e.Seq, prevSeq)
		}
		if pe.TS.Before(prevTS) {
			t.Fatalf("ts not ordered: %s after %s", pe.TS, prevTS)
		}
		if pe.TS.Before(start) || !pe.TS.Before(start.Add(24*time.Hour)) {
			t.Fatalf("ts out of window: %s", pe.TS)
		}
		prevSeq, prevTS = e.Seq, pe.TS
	}
	for _, typ := range catalog {
		if counts[typ] == 0 {
			t.Errorf("type %s never generated", typ)
		}
	}
	if counts["net.dns"] < 5000 || counts["net.connect"] < 4000 {
		t.Errorf("traffic too low: %d dns, %d connect", counts["net.dns"], counts["net.connect"])
	}
	if counts["agent.heartbeat"] < 95 || counts["agent.heartbeat"] > 97 {
		t.Errorf("heartbeats: %d", counts["agent.heartbeat"])
	}
	if sev[2] == 0 || sev[3] == 0 {
		t.Errorf("severities: %v", sev)
	}
	if counts["net.wifi"] < 4 {
		t.Errorf("weekday without wifi changes: %d", counts["net.wifi"])
	}
	t.Logf("%d events, %d types, sev %v", len(evs), len(counts), sev)
}

func TestTrackStaysAroundParis(t *testing.T) {
	start := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) // Saturday
	for _, e := range generate(t, start, 24*time.Hour) {
		if e.Type != "location.fix" {
			continue
		}
		lat, lon := e.Data["lat"].(float64), e.Data["lon"].(float64)
		if lat < 48.80 || lat > 48.92 || lon < 2.10 || lon > 2.46 {
			t.Fatalf("fix outside Paris: %v,%v", lat, lon)
		}
	}
}

func TestULID(t *testing.T) {
	g := New(Options{Start: time.Now(), Seed: 1})
	ts := time.Date(2026, 11, 15, 21, 43, 3, 974e6, time.UTC)
	id := NewULID(ts, g.rng)
	if len(id) != 26 || id[0] > '7' {
		t.Fatalf("bad ULID %s", id)
	}
	// The first 10 characters encode the timestamp.
	const enc = crockford
	var ms uint64
	for _, c := range id[:10] {
		for i := range enc {
			if enc[i] == byte(c) {
				ms = ms<<5 | uint64(i)
			}
		}
	}
	if int64(ms) != ts.UnixMilli() {
		t.Fatalf("timestamp %d != %d", ms, ts.UnixMilli())
	}
}

// The parts of one inventory share an inventory_id (contract §2), distinct per inventory.
func TestInventoryID(t *testing.T) {
	start := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	byID := map[string][]int{}
	parts := 0
	for _, e := range generate(t, start, 48*time.Hour) {
		if e.Type != "app.inventory" {
			continue
		}
		id, _ := e.Data["inventory_id"].(string)
		if len(id) != 26 {
			t.Fatalf("inventory_id %q", e.Data["inventory_id"])
		}
		byID[id] = append(byID[id], e.Data["part"].(int))
		parts = e.Data["parts"].(int)
	}
	if len(byID) < 2 {
		t.Fatalf("%d inventories in 48 h", len(byID))
	}
	for id, ps := range byID {
		if len(ps) != parts {
			t.Fatalf("inventory %s has parts %v, want %d", id, ps, parts)
		}
	}
}

// security.posture_change: one event per changed field, consistent with the successive postures.
func TestPostureChanges(t *testing.T) {
	start := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	evs := generate(t, start, 24*time.Hour)
	var prev map[string]string
	pending := map[string]bool{} // fields announced by the last posture, awaiting their change event
	seen := map[string]int{}
	for _, e := range evs {
		switch e.Type {
		case "security.posture":
			if len(pending) > 0 {
				t.Fatalf("posture changes missing before %s: %v", e.TS, pending)
			}
			cur := map[string]string{}
			for k, v := range e.Data {
				cur[k] = postureString(v)
			}
			if prev != nil {
				for k, v := range cur {
					if k != "patch_age_days" && prev[k] != v {
						pending[k] = true
					}
				}
			}
			prev = cur
		case "security.posture_change":
			f, _ := e.Data["field"].(string)
			if !pending[f] {
				t.Fatalf("unexpected posture_change %v", e.Data)
			}
			if _, ok := e.Data["old"].(string); !ok {
				t.Fatalf("old not a string: %v", e.Data)
			}
			if e.Data["new"] != prev[f] {
				t.Fatalf("new %v != posture %q", e.Data["new"], prev[f])
			}
			delete(pending, f)
			seen[f]++
		}
	}
	for _, f := range []string{"adb_enabled", "dev_options", "user_ca_certs", "unknown_sources", "play_protect", "private_dns_mode", "private_dns_host"} {
		if seen[f] == 0 {
			t.Errorf("no posture_change for %s (%v)", f, seen)
		}
	}
}

// sensor.camera / sensor.microphone carry screen_on and locked; some use happens screen off and locked.
func TestSensorScreenState(t *testing.T) {
	start := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	hidden := 0
	for _, e := range generate(t, start, 24*time.Hour) {
		if e.Type != "sensor.camera" && e.Type != "sensor.microphone" {
			continue
		}
		on, ok1 := e.Data["screen_on"].(bool)
		locked, ok2 := e.Data["locked"].(bool)
		if !ok1 || !ok2 {
			t.Fatalf("%s without screen_on/locked: %v", e.Type, e.Data)
		}
		if (e.Data["recording"] == true || e.Data["in_use"] == true) && !on && locked {
			hidden++
		}
	}
	if hidden < 2 {
		t.Errorf("only %d camera/microphone uses with the screen off and locked", hidden)
	}
}

// security.log payloads follow the table of the contract.
func TestSecurityLogFields(t *testing.T) {
	allowed := map[string][]string{
		"adb_shell_interactive": {}, "adb_shell_cmd": {"command"}, "sync_recv_file": {"path"}, "sync_send_file": {"path"},
		"app_process_start":  {"process", "start_time", "uid", "pid", "seinfo", "apk_sha256"},
		"keyguard_dismissed": {}, "keyguard_secured": {},
		"keyguard_dismiss_auth_attempt": {"success", "strength"},
		"os_startup":                    {"verified_boot_state", "dm_verity_mode"}, "os_shutdown": {},
		"logging_started": {}, "logging_stopped": {}, "log_buffer_size_critical": {},
		"media_mount": {"mount_point", "label"}, "media_unmount": {"mount_point", "label"},
		"crypto_self_test_completed": {"success"},
		"key_generated":              {"success", "alias", "uid"}, "key_import": {"success", "alias", "uid"}, "key_destruction": {"success", "alias", "uid"},
		"key_integrity_violation":  {"alias", "uid"},
		"cert_authority_installed": {"success", "subject", "user_id"}, "cert_authority_removed": {"success", "subject", "user_id"},
		"cert_validation_failure": {"reason"},
		"user_restriction_added":  {"admin_package", "user_id", "restriction"}, "user_restriction_removed": {"admin_package", "user_id", "restriction"},
		"password_changed": {"complexity", "user_id"},
		"wifi_connection":  {"bssid", "event_type", "reason"}, "wifi_disconnection": {"bssid", "reason"},
		"bluetooth_connection": {"address", "success", "reason"}, "bluetooth_disconnection": {"address", "reason"},
		"package_installed": {"package", "version_code", "user_id"}, "package_updated": {"package", "version_code", "user_id"},
		"package_uninstalled": {"package", "version_code", "user_id"},
	}
	start := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	tags := map[string]int{}
	for _, e := range generate(t, start, 24*time.Hour) {
		if e.Type != "security.log" {
			continue
		}
		tag, _ := e.Data["tag"].(string)
		tags[tag]++
		names, ok := allowed[tag]
		if !ok {
			t.Fatalf("tag %q not in the contract table", tag)
		}
		fields, _ := e.Data["fields"].(map[string]any)
		for k, v := range fields {
			if !slices.Contains(names, k) {
				t.Fatalf("tag %s: field %q not in the contract (%v)", tag, k, names)
			}
			if k == "success" {
				if _, ok := v.(bool); !ok {
					t.Fatalf("tag %s: success must be a boolean, got %T", tag, v)
				}
			}
		}
	}
	for _, tag := range []string{"adb_shell_interactive", "adb_shell_cmd", "sync_recv_file", "keyguard_dismiss_auth_attempt",
		"cert_authority_installed", "media_mount", "package_installed", "app_process_start"} {
		if tags[tag] == 0 {
			t.Errorf("tag %s never generated", tag)
		}
	}
}

// The private DNS host comes from the enrollment file.
func TestPrivateDNSHostFromOptions(t *testing.T) {
	start := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	evs := generateOpts(t, Options{Start: start, Seed: 7, Rate: 0.2, SeqBase: 1, PrivateDNSHost: "dns.essai.test"}, 6*time.Hour)
	n := 0
	for _, e := range evs {
		switch e.Type {
		case "security.posture":
			if h := e.Data["private_dns_host"]; h != "dns.essai.test" && h != "" {
				t.Fatalf("posture private_dns_host %v", h)
			}
			n++
		case "net.connectivity":
			if e.Data["private_dns_server"] != "dns.essai.test" {
				t.Fatalf("connectivity private_dns_server %v", e.Data["private_dns_server"])
			}
		case "security.policy":
			if e.Data["action"] == "private_dns_set" && e.Data["target"] != "dns.essai.test" {
				t.Fatalf("policy target %v", e.Data["target"])
			}
		}
	}
	if n == 0 {
		t.Fatal("no posture generated")
	}
}
