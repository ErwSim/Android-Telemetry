package sim

import (
	"encoding/json"
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
	"security.log", "security.posture", "security.keyguard", "security.ca_cert", "security.policy",
}

func generate(t *testing.T, start time.Time, span time.Duration) []Event {
	t.Helper()
	g := New(Options{Start: start, Seed: 42, Rate: 1, SeqBase: 1000})
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
