package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

func (e *env) mute(c *http.Cookie, method string, body map[string]any) *http.Response {
	b, _ := json.Marshal(body)
	rec := e.do(method, "/api/console/detections/mute", bytes.NewReader(b), withCookie(c), withHeader("X-Requested-With", "vigie"),
		withHeader("Content-Type", "application/json"))
	return rec.Result()
}

// Contract §11.4: the owner's attack without app.ops (a Play Store application that obtains SEND_SMS 30 h after
// its installation and sends in bulk) is reported by detect.sms_permission; being made the default SMS app by
// detect.default_app_changed; an inventory that passes an installed application off as a system one is reported
// and does not hide it.
func TestDetectionsWithoutAppOps(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	h := time.Now().UTC().Truncate(time.Hour).Add(-40 * time.Hour)
	const app = "com.coupons.promo.deals"
	inv := func(at time.Time, apps ...map[string]any) map[string]any {
		return e.event(at, "app.inventory", 0, map[string]any{"inventory_id": model.NewULID(at), "part": 1, "parts": 1, "apps": apps})
	}
	messaging := map[string]any{"package": "com.samsung.android.messaging", "label": "Messages", "system": true, "installer": "",
		"granted_dangerous": []string{"android.permission.SEND_SMS"}}
	e.ingestAll([]map[string]any{
		e.event(h, "app.special_access", 0, map[string]any{"default_apps": map[string]any{"sms": "com.samsung.android.messaging"}}),
		inv(h.Add(time.Minute), messaging),
		e.event(h.Add(2*time.Minute), "app.installed", 0, map[string]any{"package": app, "installer": "com.android.vending"}),
		e.event(h.Add(2*time.Minute), "app.risk", 1, map[string]any{"package": app, "label": "Promo Coupons", "score": 45, "level": "medium",
			"reasons": []string{"no_launcher_icon", "sms_send", "boot_receiver"}, "granted": []string{}}),
	})
	if n := e.runDetections(); n != 0 {
		t.Fatalf("before the grant: %d", n)
	}
	grant := h.Add(30 * time.Hour)
	e.ingestAll([]map[string]any{e.event(grant, "app.permission_changed", 1, map[string]any{"package": app, "permission": "android.permission.SEND_SMS", "granted": true})})
	if n := e.runDetections(); n != 1 {
		t.Fatalf("grant: %d", n)
	}
	items, _ := e.detections(c, nil)
	if items[0].Type != "detect.sms_permission" || items[0].Package != app || items[0].Severity != 2 || items[0].WindowFrom != model.FormatTS(grant) {
		t.Fatalf("%+v", items)
	}
	// The next inventories still show the permission: nothing new. Revoked then granted again: a second one.
	holder := map[string]any{"package": app, "installer": "com.android.vending", "system": false, "granted_dangerous": []string{"android.permission.SEND_SMS"}}
	e.ingestAll([]map[string]any{inv(grant.Add(2*time.Hour), messaging, holder)})
	if n := e.runDetections(); n != 0 {
		t.Fatalf("inventory after the grant: %d", n)
	}
	e.ingestAll([]map[string]any{
		e.event(grant.Add(3*time.Hour), "app.permission_changed", 0, map[string]any{"package": app, "permission": "android.permission.SEND_SMS", "granted": false}),
		e.event(grant.Add(4*time.Hour), "app.permission_changed", 1, map[string]any{"package": app, "permission": "android.permission.SEND_SMS", "granted": true}),
	})
	if n := e.runDetections(); n != 1 {
		t.Fatalf("granted again: %d", n)
	}
	// Made the default SMS app: severity 3, with the risk profile of the new application.
	e.ingestAll([]map[string]any{e.event(grant.Add(5*time.Hour), "app.role", 2, map[string]any{"role": "sms", "old": "com.samsung.android.messaging", "new": app})})
	if n := e.runDetections(); n != 1 {
		t.Fatalf("role: %d", n)
	}
	list, _ := e.detections(c, url.Values{"type": {"detect.default_app_changed"}})
	if len(list) != 1 || list[0].Severity != 3 || list[0].Evidence["new"] != app || list[0].Evidence["level"] != "medium" {
		t.Fatalf("%+v", list)
	}
	// An inventory claiming that an installed application is a system one.
	fake := map[string]any{"package": "com.fake.system", "installer": "com.google.android.packageinstaller", "system": true,
		"granted_dangerous": []string{"android.permission.SEND_SMS"}}
	e.ingestAll([]map[string]any{inv(grant.Add(6*time.Hour), messaging, holder, fake)})
	if n := e.runDetections(); n != 2 {
		t.Fatalf("system claim: %d", n)
	}
	got := byType(func() []detItem { l, _ := e.detections(c, url.Values{"package": {"com.fake.system"}}); return l }())
	if len(got["detect.inventory_mismatch"]) != 1 || got["detect.inventory_mismatch"][0].Severity != 3 || len(got["detect.sms_permission"]) != 1 {
		t.Fatalf("%+v", got)
	}
}

// Contract §11.4: mutes, recurrence and the daily cap.
func TestDetectionsMuteRecurrenceFlood(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	dev := e.dev.DeviceID
	day := time.Now().UTC().Truncate(24 * time.Hour)
	bypass := func(at time.Time, pkg string) map[string]any {
		return e.event(at, "net.connect", 0, map[string]any{"package": pkg, "uid": 10500, "ip": "1.1.1.1", "port": 443})
	}
	// Recurrence: the same application again 3 days later: recurring, severity 1.
	e.ingestAll([]map[string]any{bypass(day.Add(-72*time.Hour+time.Hour), "org.mozilla.firefox")})
	e.runDetections()
	e.ingestAll([]map[string]any{bypass(day.Add(-24*time.Hour+time.Hour), "org.mozilla.firefox")})
	if n := e.runDetections(); n != 1 {
		t.Fatalf("second day: %d", n)
	}
	list, _ := e.detections(c, url.Values{"type": {"detect.dns_bypass"}})
	if len(list) != 2 || !list[0].Recurring || list[0].Severity != 1 || list[1].Recurring || list[1].Severity != 2 {
		t.Fatalf("recurrence %+v", list)
	}
	evs := e.serverEvents(c, "detect.dns_bypass")
	if d := evs[0]["data"].(map[string]any); d["recurring"] != true || evs[0]["sev"] != float64(1) {
		t.Fatalf("recurring event %v", evs[0])
	}

	// Mute: validation, then the next detection is stored muted, neither exported nor streamed.
	for _, tc := range []struct {
		body map[string]any
		code int
	}{
		{map[string]any{"device_id": dev, "type": "detect.sms_abuse", "package": "x.y"}, 400},
		{map[string]any{"device_id": dev, "type": "detect.default_app_changed", "package": "x.y"}, 400},
		{map[string]any{"device_id": dev, "type": "detect.nope", "package": "x.y"}, 400},
		{map[string]any{"device_id": dev, "type": "detect.dns_bypass"}, 400},
		{map[string]any{"device_id": "dev_autre", "type": "detect.dns_bypass", "package": "x.y"}, 404},
		{map[string]any{"device_id": dev, "type": "detect.dns_bypass", "package": "x.y", "extra": 1}, 400},
	} {
		if r := e.mute(c, http.MethodPost, tc.body); r.StatusCode != tc.code {
			t.Errorf("%v: %d", tc.body, r.StatusCode)
		}
	}
	m := map[string]any{"device_id": dev, "type": "detect.dns_bypass", "package": "org.mozilla.firefox", "reason": "DoH voulu dans Firefox"}
	if r := e.mute(c, http.MethodPost, m); r.StatusCode != http.StatusNoContent {
		t.Fatalf("mute: %d", r.StatusCode)
	}
	if r := e.mute(c, http.MethodPost, m); r.StatusCode != http.StatusNoContent {
		t.Fatalf("mute again: %d", r.StatusCode)
	}
	rec := e.get(c, "/api/console/detections/mutes", nil)
	var mutes struct{ Mutes []store.Mute }
	if json.Unmarshal(rec.Body.Bytes(), &mutes) != nil || len(mutes.Mutes) != 1 || mutes.Mutes[0].Reason != "DoH voulu dans Firefox" || mutes.Mutes[0].CreatedBy != "admin" {
		t.Fatalf("mutes %s", rec.Body)
	}
	if n := len(e.serverEvents(c, "detect.muted")); n != 1 {
		t.Fatalf("detect.muted events: %d", n)
	}
	before := len(e.serverEvents(c, "detect.dns_bypass"))
	e.ingestAll([]map[string]any{bypass(day.Add(time.Hour), "org.mozilla.firefox")})
	e.runDetections()
	list, _ = e.detections(c, url.Values{"type": {"detect.dns_bypass"}})
	if len(list) != 3 || !list[0].Muted || !list[1].Muted || len(e.serverEvents(c, "detect.dns_bypass")) != before {
		t.Fatalf("muted detection exported or not stored: %+v", list)
	}
	if r := e.mute(c, http.MethodDelete, m); r.StatusCode != http.StatusNoContent {
		t.Fatalf("unmute: %d", r.StatusCode)
	}
	if r := e.mute(c, http.MethodDelete, m); r.StatusCode != http.StatusNotFound {
		t.Fatalf("unmute again: %d", r.StatusCode)
	}
	if n := len(e.serverEvents(c, "detect.unmuted")); n != 1 {
		t.Fatalf("detect.unmuted events: %d", n)
	}

	// Cap: 250 applications reaching the fanout threshold in one hour → 200 detections and one detect.flood.
	h := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	var flood []map[string]any
	for i := range 250 {
		pkg := fmt.Sprintf("com.flood.app%03d", i)
		flood = append(flood, e.connects(h.Add(time.Duration(i)*time.Second), pkg, 301, 443, fmt.Sprintf("10.%d", i))...)
	}
	e.ingestDirect(flood)
	e.runDetections()
	all, _, err := e.st.ListDetections(context.Background(), store.DetectionQuery{FromMS: 0, ToMS: time.Now().Add(time.Hour).UnixMilli(), Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, d := range all {
		counts[d.Type]++
	}
	if counts["detect.flood"] != 1 || len(all)-1 != store.MaxDetectionsPerDay {
		t.Fatalf("cap: %d detections %v", len(all), counts)
	}
	fl, _ := e.detections(c, url.Values{"type": {"detect.flood"}})
	if fl[0].Severity != 3 || fl[0].Evidence["suppressed"] == nil {
		t.Fatalf("flood %+v", fl)
	}
}

// ingestDirect stores events through the store (no rate limit), as the ingestion does.
func (e *env) ingestDirect(evs []map[string]any) {
	e.t.Helper()
	now := time.Now()
	for len(evs) > 0 {
		n := min(len(evs), 500)
		batch := make([]*model.Event, 0, n)
		for _, m := range evs[:n] {
			raw, _ := json.Marshal(m)
			ev, err := model.ParseEvent(raw, now)
			if err != nil {
				e.t.Fatal(err)
			}
			batch = append(batch, ev)
		}
		if _, err := e.st.Ingest(context.Background(), e.dev.DeviceID, "test", batch, now); err != nil {
			e.t.Fatal(err)
		}
		evs = evs[n:]
	}
}
