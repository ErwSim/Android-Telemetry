package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/adguard"
	"github.com/erwsim/android-telemetry/server/collector/internal/model"
)

type detItem struct {
	ID, TS, Type, Package, Label, Summary string
	DeviceID                              string `json:"device_id"`
	Severity                              int
	Evidence                              map[string]any
	WindowFrom                            string `json:"window_from"`
	WindowTo                              string `json:"window_to"`
}

func (e *env) detections(c *http.Cookie, q url.Values) ([]detItem, string) {
	e.t.Helper()
	rec := e.get(c, "/api/console/detections", q)
	if rec.Code != http.StatusOK {
		e.t.Fatalf("detections: %d %s", rec.Code, rec.Body)
	}
	var r struct {
		Detections []detItem `json:"detections"`
		NextCursor string    `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		e.t.Fatal(err)
	}
	return r.Detections, r.NextCursor
}

func (e *env) runDetections() int {
	e.t.Helper()
	st, err := e.srv.detector.RunOnce(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	if st.Remaining {
		e.t.Fatal("detection run did not finish")
	}
	return st.Findings
}

func byType(items []detItem) map[string][]detItem {
	out := map[string][]detItem{}
	for _, d := range items {
		out[d.Type] = append(out[d.Type], d)
	}
	return out
}

// connects builds n net.connect events of pkg to n distinct addresses on port within the minute after at.
func (e *env) connects(at time.Time, pkg string, n, port int, prefix string) []map[string]any {
	var out []map[string]any
	for i := range n {
		out = append(out, e.event(at.Add(time.Duration(i)*100*time.Millisecond), "net.connect", 0,
			map[string]any{"package": pkg, "uid": 10400, "ip": fmt.Sprintf("%s.%d.%d", prefix, i/250, 1+i%250), "port": port}))
	}
	return out
}

func (e *env) ingestAll(evs []map[string]any) {
	e.t.Helper()
	for len(evs) > 0 {
		n := min(len(evs), 500)
		if r := e.ingest(evs[:n]); r.Accepted+r.Duplicates != n {
			e.t.Fatalf("ingest: %+v", r)
		}
		evs = evs[n:]
	}
}

func TestDetectionsEndToEnd(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	now := time.Now().UTC()
	h := now.Truncate(time.Hour).Add(-3 * time.Hour) // a complete hour, within the same day or the day before
	sub, err := e.srv.broker.Subscribe("")
	if err != nil {
		t.Fatal(err)
	}
	defer e.srv.broker.Unsubscribe(sub)

	var evs []map[string]any
	// Screen off for the whole hour.
	evs = append(evs, e.event(h.Add(-10*time.Minute), "device.screen", 0, map[string]any{"state": "off"}))
	// Roles and inventory: the default SMS app and the system apps.
	evs = append(evs, e.event(h.Add(-20*time.Minute), "app.role", 0, map[string]any{"role": "sms", "new": "com.samsung.android.messaging"}),
		e.event(h.Add(-19*time.Minute), "app.inventory", 0, map[string]any{"inventory_id": "inv1", "part": 1, "parts": 1, "apps": []map[string]any{
			{"package": "com.samsung.android.messaging", "label": "Messages", "system": true},
			{"package": "com.flashlight.pro", "label": "Lampe Pro", "system": false}}}))
	// detect.fanout: 150 distinct addresses screen off (threshold 100); Chrome with 80 stays below.
	evs = append(evs, e.connects(h.Add(5*time.Minute), "com.proxy.sdk", 150, 443, "198.51")...)
	evs = append(evs, e.connects(h.Add(6*time.Minute), "com.android.chrome", 80, 443, "203.0")...)
	// detect.mail_ports: 40 connections to port 587; Samsung Email to 465 is a mail client.
	evs = append(evs, e.connects(h.Add(7*time.Minute), "com.cleaner.boost", 40, 587, "192.0")...)
	evs = append(evs, e.connects(h.Add(8*time.Minute), "com.samsung.android.email.provider", 2, 465, "203.0")...)
	// detect.dns_bypass: Cloudflare over HTTPS.
	evs = append(evs, e.event(h.Add(9*time.Minute), "net.connect", 0, map[string]any{"package": "com.secure.browser", "uid": 10500, "ip": "1.1.1.1", "port": 443, "count": 12}))
	// detect.upload_spike: 3 GiB in one hour (learning: the floor alone).
	evs = append(evs, e.event(h.Add(59*time.Minute), "net.usage", 0, map[string]any{"from": model.FormatTS(h), "to": model.FormatTS(h.Add(time.Hour)),
		"apps": []map[string]any{{"package": "com.gallery.vault", "uid": 10600, "rx_bytes": 1 << 20, "tx_bytes": 3 << 30, "transport": "wifi"},
			{"package": "com.whatsapp", "uid": 10251, "rx_bytes": 1 << 20, "tx_bytes": 900 << 20, "transport": "wifi"}}}))
	// detect.new_app_risky + detect.sms_abuse + detect.sensor_background.
	inst := h.Add(10 * time.Minute)
	evs = append(evs, e.event(inst, "app.installed", 0, map[string]any{"package": "com.flashlight.pro", "version_code": 3, "installer": "com.google.android.packageinstaller"}),
		e.event(inst.Add(time.Second), "app.risk", 2, map[string]any{"package": "com.flashlight.pro", "label": "Lampe Pro", "version_code": 3,
			"installer": "com.google.android.packageinstaller", "from_store": false, "score": 88, "level": "high",
			"reasons": []string{"sideloaded", "no_launcher_icon", "sms_send", "boot_receiver", "combo_sms_fraud"}}),
		e.event(inst.Add(4*time.Minute), "app.permission_changed", 0, map[string]any{"package": "com.flashlight.pro", "permission": "android.permission.SEND_SMS", "granted": true}),
		e.event(inst.Add(5*time.Minute), "app.risk", 0, map[string]any{"package": "com.whatsapp", "label": "WhatsApp", "score": 15, "level": "low", "reasons": []string{"boot_receiver"}}),
		e.event(h.Add(59*time.Minute), "app.ops", 0, map[string]any{"from": model.FormatTS(h), "to": model.FormatTS(h.Add(time.Hour)), "apps": []map[string]any{
			{"package": "com.flashlight.pro", "op": "send_sms", "count": 95, "background_count": 95, "last_ts": model.FormatTS(h.Add(58 * time.Minute))},
			{"package": "com.flashlight.pro", "op": "read_contacts", "count": 2, "background_count": 2},
			{"package": "com.flashlight.pro", "op": "record_audio", "count": 14, "background_count": 12},
			{"package": "com.samsung.android.messaging", "op": "send_sms", "count": 4, "background_count": 0},
		}}))
	e.ingestAll(evs)

	if n := e.runDetections(); n != 7 {
		items, _ := e.detections(c, nil)
		t.Fatalf("findings: %d %+v", n, items)
	}
	items, next := e.detections(c, nil)
	got := byType(items)
	want := map[string]string{
		"detect.fanout": "com.proxy.sdk", "detect.mail_ports": "com.cleaner.boost", "detect.dns_bypass": "com.secure.browser",
		"detect.upload_spike": "com.gallery.vault", "detect.sms_abuse": "com.flashlight.pro", "detect.sensor_background": "com.flashlight.pro",
	}
	for typ, pkg := range want {
		if len(got[typ]) != 1 || got[typ][0].Package != pkg {
			t.Errorf("%s: %+v", typ, got[typ])
		}
	}
	if len(items) != 7 || next != "" || len(got["detect.new_app_risky"]) != 1 {
		t.Fatalf("detections %d %+v", len(items), got["detect.new_app_risky"])
	}
	f := got["detect.fanout"][0]
	day := h.Truncate(24 * time.Hour)
	if f.Evidence["addresses"] != float64(150) || f.Evidence["screen_on_minutes"] != float64(0) || f.WindowFrom != model.FormatTS(day) ||
		f.WindowTo != model.FormatTS(day.Add(24*time.Hour)) || f.Evidence["peak_hour"] != model.FormatTS(h) || f.Evidence["hours"] != float64(1) ||
		f.Severity != 2 || f.DeviceID != e.dev.DeviceID || f.ID == "" {
		t.Fatalf("fanout %+v", f)
	}
	if s := got["detect.sms_abuse"][0]; s.Label != "Lampe Pro" || s.Evidence["reason"] != "not_default_sms_app" || s.Severity != 3 ||
		!strings.Contains(s.Summary, "95 SMS") {
		t.Fatalf("sms %+v", s)
	}
	if u := got["detect.upload_spike"][0]; u.Evidence["learning"] != true || u.Evidence["tx_bytes"] != float64(3<<30) {
		t.Fatalf("upload %+v", u)
	}

	// Stored as events of the collector (source "server"), streamed, with the fields of contract §11.3.
	evts := e.serverEvents(c, "detect.")
	if len(evts) != 7 || evts[0]["source"] != "server" {
		t.Fatalf("server events %d", len(evts))
	}
	for _, ev := range evts {
		d := ev["data"].(map[string]any)
		if d["window_from"] == nil || d["window_to"] == nil || d["evidence"] == nil || d["summary"] == nil || d["package"] == nil {
			t.Fatalf("event data %v", d)
		}
	}
	streamed := 0
	for len(sub.ch) > 0 {
		if b := <-sub.ch; strings.Contains(string(b), `"type":"detect.`) {
			streamed++
		}
	}
	if streamed != 7 {
		t.Fatalf("streamed detections: %d", streamed)
	}

	if nr := got["detect.new_app_risky"][0]; nr.Severity != 3 || nr.Evidence["high_risk"] != true ||
		len(nr.Evidence["capabilities"].([]any)) != 1 || nr.WindowFrom != model.FormatTS(inst) {
		t.Fatalf("new app %+v", nr)
	}

	// Idempotence: running again, a restart (new engine), and new data in the same windows add no detection;
	// more data updates the detection in place, without a new event (no new element, same severity).
	if n := e.runDetections(); n != 0 {
		t.Fatalf("second run: %d", n)
	}
	e.srv.detector = e.srv.newDetector()
	e.ingestAll(e.connects(h.Add(30*time.Minute), "com.proxy.sdk", 200, 443, "100.64"))
	if n := e.runDetections(); n != 0 {
		t.Fatalf("after restart and more data: %d", n)
	}
	if list, _ := e.detections(c, url.Values{"type": {"detect.fanout"}}); len(list) != 1 || list[0].Evidence["addresses"] != float64(350) ||
		list[0].ID != f.ID {
		t.Fatalf("fanout not updated in place: %+v", list)
	}
	if n := len(e.serverEvents(c, "detect.")); n != 7 {
		t.Fatalf("update exported: %d events", n)
	}

	// A late batch, three days old: evaluated when it arrives.
	old := h.Add(-72 * time.Hour)
	e.ingestAll(e.connects(old.Add(time.Minute), "com.proxy.sdk", 320, 8080, "100.65"))
	if n := e.runDetections(); n != 1 {
		t.Fatalf("late batch: %d", n)
	}
	late, _ := e.detections(c, url.Values{"type": {"detect.fanout"}})
	if len(late) != 2 || late[0].WindowFrom != model.FormatTS(old.Truncate(24*time.Hour)) || late[0].Evidence["addresses"] != float64(320) {
		t.Fatalf("late %+v", late)
	}

	// Filters and cursor.
	if list, _ := e.detections(c, url.Values{"type": {"detect.sms_abuse,detect.mail_ports"}}); len(list) != 2 {
		t.Fatalf("type filter %d", len(list))
	}
	var all []string
	cursor := ""
	for range 20 {
		q := url.Values{"limit": {"3"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		page, nc := e.detections(c, q)
		for _, d := range page {
			all = append(all, d.ID)
		}
		if nc == "" {
			break
		}
		cursor = nc
	}
	if len(all) != 8 {
		t.Fatalf("paged %d", len(all))
	}
	if list, _ := e.detections(c, url.Values{"package": {"com.cleaner.boost"}}); len(list) != 1 || list[0].Type != "detect.mail_ports" {
		t.Fatalf("package filter %+v", list)
	}
	if rec := e.get(c, "/api/console/detections", url.Values{"package": {"a b"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad package: %d", rec.Code)
	}
	if list, _ := e.detections(c, url.Values{"device_id": {"dev_autre"}}); len(list) != 0 {
		t.Fatal("device filter")
	}
	if rec := e.get(c, "/api/console/detections", url.Values{"cursor": {"!!"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad cursor: %d", rec.Code)
	}
	if rec := e.get(nil, "/api/console/detections", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("without session: %d", rec.Code)
	}

	// GET /apps/risk: latest app.risk per application, highest score first.
	rec := e.get(c, "/api/console/apps/risk", url.Values{"device_id": {e.dev.DeviceID}})
	var risk struct {
		Apps []map[string]any `json:"apps"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &risk) != nil || len(risk.Apps) != 2 ||
		risk.Apps[0]["package"] != "com.flashlight.pro" || risk.Apps[0]["level"] != "high" || risk.Apps[1]["score"] != float64(15) {
		t.Fatalf("apps/risk %d %s", rec.Code, rec.Body)
	}
	if rec := e.get(c, "/api/console/apps/risk", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("apps/risk without device: %d", rec.Code)
	}
	// GET /apps/ops: per application and operation.
	rec = e.get(c, "/api/console/apps/ops", url.Values{"device_id": {e.dev.DeviceID}, "from": {model.FormatTS(h.Add(10 * time.Minute))},
		"to": {model.FormatTS(h.Add(2 * time.Hour))}})
	var ops struct {
		Apps []struct {
			Package, Label string
			Count          int64
			Ops            []struct {
				Op         string
				Count      int64
				Background int64 `json:"background_count"`
			}
		} `json:"apps"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ops) != nil || len(ops.Apps) != 2 || ops.Apps[0].Package != "com.flashlight.pro" ||
		ops.Apps[0].Count != 111 || ops.Apps[0].Ops[0].Op != "send_sms" || ops.Apps[0].Ops[0].Background != 95 || ops.Apps[0].Label != "Lampe Pro" {
		t.Fatalf("apps/ops %d %s", rec.Code, rec.Body)
	}
	if rec := e.get(c, "/api/console/apps/ops", url.Values{"device_id": {e.dev.DeviceID}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("apps/ops without from/to: %d", rec.Code)
	}
}

// Below every threshold, and without app.ops (experimental, may never come): nothing, and no error.
func TestDetectionsQuietBelowThresholds(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	h := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	var evs []map[string]any
	evs = append(evs, e.event(h.Add(-time.Minute), "device.screen", 0, map[string]any{"state": "off"}))
	evs = append(evs, e.connects(h.Add(time.Minute), "com.proxy.sdk", 100, 443, "198.51")...) // 100 = the screen-off threshold
	evs = append(evs, e.connects(h.Add(2*time.Minute), "com.samsung.android.email.provider", 5, 587, "203.0")...)
	evs = append(evs, e.event(h.Add(3*time.Minute), "net.connect", 0, map[string]any{"package": "com.game", "uid": 10700, "ip": "8.8.8.8", "port": 53}))
	evs = append(evs, e.event(h.Add(59*time.Minute), "net.usage", 0, map[string]any{"from": model.FormatTS(h), "to": model.FormatTS(h.Add(time.Hour)),
		"apps": []map[string]any{{"package": "com.google.android.apps.photos", "uid": 10601, "rx_bytes": 1, "tx_bytes": 1 << 30, "transport": "wifi"}}}))
	evs = append(evs, e.event(h.Add(4*time.Minute), "app.installed", 0, map[string]any{"package": "fr.vinted", "installer": "com.android.vending"}),
		e.event(h.Add(4*time.Minute), "app.risk", 0, map[string]any{"package": "fr.vinted", "score": 30, "level": "medium", "reasons": []string{"boot_receiver"}}),
		e.event(h.Add(5*time.Minute), "app.permission_changed", 0, map[string]any{"package": "fr.vinted", "permission": "android.permission.CAMERA", "granted": true}))
	e.ingestAll(evs)
	if n := e.runDetections(); n != 0 {
		items, _ := e.detections(c, nil)
		t.Fatalf("findings below thresholds: %+v", items)
	}
	if n, err := e.st.DirtyCount(context.Background()); err != nil || n != 0 {
		t.Fatalf("dirty hours left: %d %v", n, err)
	}
	// Disabled detection: nothing even above its threshold.
	e2 := newEnv(t, map[string]string{"VIGIE_DETECT_DISABLE": "fanout"})
	e2.ingestAll(e2.connects(h.Add(time.Minute), "com.proxy.sdk", 400, 443, "198.51"))
	if n := e2.runDetections(); n != 0 {
		t.Fatalf("disabled detection: %d", n)
	}
}

// detect.threat_domain: net.dns of the phone crossed with the AdGuard Home blocks due to a list of category
// "threat" (example levels file), whatever arrives first.
func TestDetectionThreatDomain(t *testing.T) {
	e, fake, _ := newTrackingEnv(t)
	c := e.session()
	ctx := context.Background()
	at := time.Now().Add(-10 * time.Minute)
	c2 := adguard.ThreatDomains[1]
	for i := range 6 {
		fake.AddQuery(at.Add(time.Duration(i)*time.Second), "192.0.2.10", "s25", c2)
	}
	fake.AddQuery(at, "192.0.2.10", "s25", "app-measurement.com") // blocked by a general list: not a threat
	if err := e.srv.tracking.pollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// AdGuard Home first: nothing to cross yet.
	if n := e.runDetections(); n != 0 {
		t.Fatalf("before net.dns: %d", n)
	}
	// The net.dns batch arrives later (1 h 30 to 2 h in reality).
	dns := func(pkg, host string, count int) map[string]any {
		return e.event(at, "net.dns", 0, map[string]any{"package": pkg, "uid": 10400, "hostname": host, "addresses": []string{"0.0.0.0"},
			"address_count": 1, "count": count})
	}
	e.ingestAll([]map[string]any{dns("com.update.system", c2, 6), dns("fr.lemonde.editorial", "app-measurement.com", 1)})
	if n := e.runDetections(); n != 1 {
		t.Fatalf("threat findings: %d", n)
	}
	items, _ := e.detections(c, nil)
	if len(items) != 1 || items[0].Type != "detect.threat_domain" || items[0].Package != "com.update.system" || items[0].Severity != 3 ||
		items[0].Evidence["domains"].([]any)[0] != c2 || items[0].Evidence["blocked"] != float64(6) ||
		!strings.Contains(items[0].Evidence["lists"].([]any)[0].(string), "Threat Intelligence") {
		t.Fatalf("%+v", items)
	}
	// AdGuard Home polled again with new blocks of the same domain: still one finding for the day.
	fake.AddQuery(time.Now().Add(-2*time.Minute), "192.0.2.10", "s25", c2)
	if err := e.srv.tracking.pollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.runDetections(); n != 0 {
		t.Fatalf("duplicate threat finding: %d", n)
	}
}
