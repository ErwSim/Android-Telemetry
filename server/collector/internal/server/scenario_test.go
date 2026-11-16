package server

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/adguard"
	"github.com/erwsim/android-telemetry/server/collector/internal/model"
	"github.com/erwsim/android-telemetry/server/collector/internal/sim"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

// simulate runs the simulator from now-span to now and stores its events like the ingestion does (directly
// in the store, batches of 500, late batches included), feeding the fake AdGuard Home when given.
func (e *env) simulate(span time.Duration, opts sim.Options, fake *adguard.Fake) int {
	e.t.Helper()
	now := time.Now().UTC()
	opts.Start, opts.SeqBase, opts.LateBatches = now.Add(-span), 1, true
	if opts.Rate == 0 {
		opts.Rate = 1
	}
	if fake != nil {
		opts.OnDNS = func(ts time.Time, host string) { fake.AddQuery(ts, "192.0.2.10", "s25", host) }
	}
	g := sim.New(opts)
	g.PlanScenario(opts.Start, now)
	total := 0
	put := func(evs []sim.Event) {
		for len(evs) > 0 {
			n := min(len(evs), 500)
			batch := make([]*model.Event, 0, n)
			for _, se := range evs[:n] {
				raw, _ := json.Marshal(se)
				ev, err := model.ParseEvent(raw, now)
				if err != nil {
					e.t.Fatalf("%s: %v", se.Type, err)
				}
				batch = append(batch, ev)
			}
			if _, err := e.st.Ingest(context.Background(), e.dev.DeviceID, "sim", batch, now); err != nil {
				e.t.Fatal(err)
			}
			total += n
			evs = evs[n:]
		}
	}
	for t := opts.Start; t.Before(now); {
		next := t.Add(6 * time.Hour)
		if next.After(now) {
			next = now
		}
		put(g.Advance(next))
		t = next
	}
	put(g.Drain())
	return total
}

func (e *env) allDetections() []detItem {
	e.t.Helper()
	ctx := context.Background()
	for range 50 {
		st, err := e.srv.detector.RunOnce(ctx)
		if err != nil {
			e.t.Fatal(err)
		}
		if !st.Remaining {
			break
		}
	}
	items, _, err := e.st.ListDetections(ctx, storeQuery())
	if err != nil {
		e.t.Fatal(err)
	}
	out := make([]detItem, 0, len(items))
	for _, d := range items {
		var ev map[string]any
		_ = json.Unmarshal(d.Evidence, &ev)
		out = append(out, detItem{ID: d.ID, Type: d.Type, Package: d.Package, Severity: d.Severity, Summary: d.Summary, Evidence: ev, WindowFrom: d.WindowFrom})
	}
	return out
}

// The measure of the false positives: weeks of a healthy simulated phone (video calls, nightly cloud
// backups, heavy browsing, mail client on port 465, app updates, a sideloaded app of medium risk, app.ops of
// the SMS app, the dialer and the assistant…) produce no detection with the default thresholds.
func TestScenarioHealthyPhoneNoDetection(t *testing.T) {
	days := 21
	if testing.Short() {
		days = 3
	}
	e, fake, _ := newTrackingEnv(t)
	n := e.simulate(time.Duration(days)*24*time.Hour, sim.Options{Seed: 20261116, Rate: 0.5, AppOps: true}, fake)
	for range 10 {
		if err := e.srv.tracking.pollOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	items := e.allDetections()
	if len(items) != 0 {
		for _, d := range items {
			t.Errorf("%s %s %s: %s", d.WindowFrom, d.Type, d.Package, d.Summary)
		}
		t.Fatalf("%d detections on a healthy phone (%d days, %d events)", len(items), days, n)
	}
	t.Logf("healthy phone: %d days, %d events, 0 detection", days, n)
}

// Each attack scenario raises the detections it is meant to, for the right application.
func TestScenarioAttacks(t *testing.T) {
	e, fake, _ := newTrackingEnv(t)
	now := time.Now().UTC()
	all, _ := sim.ParseScenarios(sim.ScenarioAll)
	e.simulate(72*time.Hour, sim.Options{Seed: 7, Rate: 0.3, AppOps: true, Scenarios: all, ScenarioStart: now.Add(-40 * time.Hour), ScenarioEnd: now}, fake)
	for range 10 {
		if err := e.srv.tracking.pollOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]map[string]int{}
	for _, d := range e.allDetections() {
		if got[d.Package] == nil {
			got[d.Package] = map[string]int{}
		}
		got[d.Package][d.Type]++
	}
	want := map[string][]string{
		"com.flashlight.pro.tools":         {"detect.new_app_risky", "detect.sms_abuse", "detect.threat_domain", "detect.sms_permission"},
		"com.android.systemupdate.service": {"detect.new_app_risky", "detect.threat_domain", "detect.default_app_changed"},
		"com.coupons.promo.deals":          {"detect.new_app_risky", "detect.sms_permission", "detect.sms_abuse"},
		"com.puzzle.relax.free":            {"detect.fanout"},
		"com.cleaner.boost.free":           {"detect.mail_ports"},
		"com.gallery.vault.hide":           {"detect.upload_spike"},
		"com.fastvpn.browser":              {"detect.dns_bypass"},
		"com.android.battery.service":      {"detect.new_app_risky", "detect.sensor_background"},
	}
	for pkg, types := range want {
		for _, typ := range types {
			if got[pkg][typ] == 0 {
				t.Errorf("%s: no %s (got %v)", pkg, typ, got[pkg])
			}
		}
	}
	// Grouped: at most one detection per application, type and day (40 hours of attacks span 3 UTC days).
	total := 0
	for pkg, m := range got {
		for typ, n := range m {
			total += n
			if n > 3 {
				t.Errorf("%s %s: %d detections, one per day expected", pkg, typ, n)
			}
		}
	}
	if total > 30 {
		t.Errorf("%d detections for 8 attacks over 40 hours", total)
	}
	var others []string
	for pkg := range got {
		if _, ok := want[pkg]; !ok {
			others = append(others, pkg)
		}
	}
	sort.Strings(others)
	if len(others) > 0 {
		t.Errorf("detections for applications outside the scenarios: %v", others)
	}
	t.Logf("detections per application: %v", got)
	if os.Getenv("VIGIE_SCENARIO_DUMP") != "" {
		for _, d := range e.allDetections() {
			t.Logf("%s %-26s %s", d.WindowFrom, d.Type, d.Summary)
		}
	}
}

func storeQuery() store.DetectionQuery {
	return store.DetectionQuery{FromMS: 0, ToMS: time.Now().Add(time.Hour).UnixMilli(), Limit: 500}
}

// The owner's attack without app.ops (contract §11.4): the application is reported when it obtains SEND_SMS
// (detect.sms_permission), after having been reported at its installation (declared capabilities: high).
func TestScenarioOwnerAttackWithoutAppOps(t *testing.T) {
	e := newEnv(t, nil)
	now := time.Now().UTC()
	e.simulate(72*time.Hour, sim.Options{Seed: 3, Rate: 0.3, AppOps: false, Scenarios: []string{sim.ScenarioSMSQuiet},
		ScenarioStart: now.Add(-60 * time.Hour), ScenarioEnd: now}, nil)
	got := map[string]int{}
	for _, d := range e.allDetections() {
		if d.Package != "com.coupons.promo.deals" {
			t.Errorf("unexpected %s %s", d.Type, d.Package)
		}
		got[d.Type]++
	}
	if len(got) != 2 || got["detect.new_app_risky"] != 1 || got["detect.sms_permission"] != 1 {
		t.Fatalf("detections %v", got)
	}
}
