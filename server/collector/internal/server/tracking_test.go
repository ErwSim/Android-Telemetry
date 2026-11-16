package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/adguard"
	"github.com/erwsim/android-telemetry/server/collector/internal/model"
	"github.com/erwsim/android-telemetry/server/collector/internal/tracking"
)

const exampleLevels = "../../examples/adguard-levels.example.json"

func newTrackingEnv(t *testing.T) (*env, *adguard.Fake, *httptest.Server) {
	t.Helper()
	fake := adguard.NewFake("vigie", "secret-adguard")
	ag := httptest.NewServer(fake)
	t.Cleanup(ag.Close)
	e := newEnv(t, map[string]string{
		"VIGIE_ADGUARD_URL": ag.URL, "VIGIE_ADGUARD_USER": "vigie", "VIGIE_ADGUARD_PASSWORD": "secret-adguard",
		"VIGIE_ADGUARD_LEVELS_FILE": exampleLevels, "VIGIE_PUBLIC_INGEST_URL": "https://ingest.vigie.example",
	})
	return e, fake, ag
}

func (e *env) trackingGet(c *http.Cookie, path string, extra url.Values) map[string]any {
	e.t.Helper()
	now := time.Now()
	q := url.Values{"from": {model.FormatTS(now.Add(-6 * time.Hour))}, "to": {model.FormatTS(now)}}
	for k, v := range extra {
		q[k] = v
	}
	rec := e.get(c, "/api/console/tracking/"+path, q)
	if rec.Code != http.StatusOK {
		e.t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		e.t.Fatal(err)
	}
	return m
}

func (e *env) put(c *http.Cookie, path string, body any, csrf bool) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	opts := []reqOpt{withCookie(c), withHeader("Content-Type", "application/json")}
	if csrf {
		opts = append(opts, withHeader("X-Requested-With", "vigie"))
	}
	return e.do(http.MethodPut, "/api/console/tracking/"+path, bytes.NewReader(b), opts...)
}

func (e *env) seedTraffic(fake *adguard.Fake, at time.Time) {
	e.t.Helper()
	dns := func(pkg, host string, count int) map[string]any {
		d := map[string]any{"package": pkg, "uid": 10100, "hostname": host, "addresses": []string{"192.0.2.1"}, "address_count": 1}
		if count > 1 {
			d["count"] = count
		}
		return e.event(at, "net.dns", 0, d)
	}
	e.ingest([]map[string]any{
		dns("fr.lemonde.editorial", "app-measurement.com", 3),
		dns("fr.lemonde.editorial", "apps.lemonde.fr", 1),
		dns("com.google.android.gms", "mtalk.google.com", 2),
		dns("com.instagram.android", "graph.facebook.com", 1),
		e.event(at, "net.usage", 0, map[string]any{"from": model.FormatTS(at.Add(-time.Hour)), "to": model.FormatTS(at), "apps": []map[string]any{
			{"package": "fr.lemonde.editorial", "uid": 10255, "rx_bytes": 8000, "tx_bytes": 800, "transport": "wifi"},
			{"package": "com.spotify.music", "uid": 10254, "rx_bytes": 90000, "tx_bytes": 1000, "transport": "wifi"},
		}}),
	})
	for i := range 3 {
		fake.AddQuery(at.Add(time.Duration(i)*time.Second), "192.0.2.10", "s25", "app-measurement.com")
	}
	fake.AddQuery(at, "192.0.2.10", "s25", "apps.lemonde.fr")
	fake.AddQuery(at, "192.0.2.10", "s25", "mtalk.google.com")
	fake.AddQuery(at, "192.0.2.10", "s25", "mtalk.google.com")
	fake.AddQuery(at, "192.0.2.10", "s25", "graph.facebook.com")
	fake.AddQuery(at, "192.0.2.10", "s25", "tracker.example") // blocked by the hand rule
}

func num(v any) int64 { f, _ := v.(float64); return int64(f) }

func TestTrackingWithAdGuard(t *testing.T) {
	e, fake, _ := newTrackingEnv(t)
	c := e.session()
	ctx := context.Background()
	at := time.Now().Add(-10 * time.Minute)
	e.seedTraffic(fake, at)
	if err := e.srv.tracking.pollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	sum := e.trackingGet(c, "summary", nil)
	tot := sum["totals"].(map[string]any)
	if sum["adguard"] != true || sum["level"] != "permissif" || num(tot["queries"]) != 8 || num(tot["blocked"]) != 4 || num(tot["allowed"]) != 4 {
		t.Fatalf("summary %v", sum)
	}
	if levels := sum["levels"].([]any); len(levels) != 3 || levels[1].(map[string]any)["key"] != "equilibre" {
		t.Fatalf("levels %v", levels)
	}
	google := sum["publishers"].([]any)[0].(map[string]any)
	if google["key"] != "google" || num(google["queries"]) != 5 || num(google["blocked"]) != 3 || num(google["apps"]) != 2 ||
		num(google["rx_bytes"]) != 6000 || num(google["tx_bytes"]) != 600 {
		t.Fatalf("google %v", google)
	}
	// Polling again counts nothing twice.
	if err := e.srv.tracking.pollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if tot := e.trackingGet(c, "summary", nil)["totals"].(map[string]any); num(tot["queries"]) != 8 {
		t.Fatalf("second poll changed totals: %v", tot)
	}
	// Domains: order, status, reason, apps, pagination.
	doms := e.trackingGet(c, "domains", url.Values{"limit": {"2"}})
	list := doms["domains"].([]any)
	first := list[0].(map[string]any)
	if first["domain"] != "app-measurement.com" || first["status"] != "blocked" || first["reason"] != "Liste : AdGuard DNS filter" ||
		first["publisher"] != "google" || len(first["apps"].([]any)) != 1 || doms["next_cursor"] == nil {
		t.Fatalf("domains %v", doms)
	}
	var all []string
	cursor := ""
	for range 10 {
		q := url.Values{"limit": {"2"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		page := e.trackingGet(c, "domains", q)
		for _, d := range page["domains"].([]any) {
			all = append(all, d.(map[string]any)["domain"].(string))
		}
		nc, _ := page["next_cursor"].(string)
		if nc == "" {
			break
		}
		cursor = nc
	}
	if !slices.Equal(all, []string{"app-measurement.com", "mtalk.google.com", "apps.lemonde.fr", "graph.facebook.com", "tracker.example"}) {
		t.Fatalf("paginated %v", all)
	}
	if hand := e.trackingGet(c, "domains", url.Values{"q": {"tracker"}})["domains"].([]any); len(hand) != 1 ||
		!strings.HasPrefix(hand[0].(map[string]any)["reason"].(string), "Règle personnalisée") {
		t.Fatalf("hand rule %v", hand)
	}
	if blocked := e.trackingGet(c, "domains", url.Values{"status": {"blocked"}, "publisher": {"google"}})["domains"].([]any); len(blocked) != 1 {
		t.Fatalf("blocked google %v", blocked)
	}
	for _, bad := range []url.Values{{"publisher": {"apple"}}, {"status": {"maybe"}}, {"limit": {"201"}}, {"cursor": {"!!"}}} {
		q := url.Values{"from": {model.FormatTS(at.Add(-time.Hour))}, "to": {model.FormatTS(time.Now())}}
		for k, v := range bad {
			q[k] = v
		}
		if rec := e.get(c, "/api/console/tracking/domains", q); rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d", bad, rec.Code)
		}
	}
	// Apps.
	apps := e.trackingGet(c, "apps", nil)["apps"].([]any)
	lm := apps[0].(map[string]any)
	if lm["package"] != "fr.lemonde.editorial" || num(lm["queries"]) != 4 || num(lm["blocked"]) != 3 || num(lm["allowed"]) != 1 ||
		num(lm["rx_bytes"]) != 8000 || len(lm["top_domains"].([]any)) != 2 {
		t.Fatalf("apps %v", apps)
	}
	if meta := e.trackingGet(c, "apps", url.Values{"publisher": {"meta"}})["apps"].([]any); len(meta) != 1 {
		t.Fatalf("meta apps %v", meta)
	}

	// Overrides: essential domain guard, managed block, idempotence, hand rules untouched.
	rec := e.put(c, "override", map[string]any{"domain": "google.com", "action": "block"}, true)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "mtalk.google.com") {
		t.Fatalf("essential: %d %s", rec.Code, rec.Body)
	}
	if rec := e.put(c, "override", map[string]any{"domain": "graph.facebook.com", "action": "block"}, false); rec.Code != http.StatusForbidden {
		t.Fatalf("without CSRF: %d", rec.Code)
	}
	for _, bad := range []map[string]any{
		{"domain": "evil.com^\n@@||google.com", "action": "block"}, {"domain": "evil.com$important", "action": "allow"},
		{"domain": "192.168.1.1", "action": "block"}, {"domain": "com", "action": "block"}, {"domain": "a.example", "action": "drop"},
		{"domain": "a.example", "action": "block", "extra": 1}, {"domain": "a.example", "action": "block", "force": "yes"},
	} {
		if rec := e.put(c, "override", bad, true); rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d %s", bad, rec.Code, rec.Body)
		}
	}
	if rec := e.put(c, "override", map[string]any{"domain": "Graph.Facebook.com.", "action": "block"}, true); rec.Code != http.StatusNoContent {
		t.Fatalf("override: %d %s", rec.Code, rec.Body)
	}
	if rec := e.put(c, "override", map[string]any{"domain": "mtalk.google.com", "action": "allow"}, true); rec.Code != http.StatusNoContent {
		t.Fatalf("allow: %d %s", rec.Code, rec.Body)
	}
	writes := fake.Requests("/control/filtering/set_rules")
	if rec := e.put(c, "override", map[string]any{"domain": "graph.facebook.com", "action": "block"}, true); rec.Code != http.StatusNoContent ||
		fake.Requests("/control/filtering/set_rules") != writes {
		t.Fatalf("idempotent override rewrote the rules: %d", rec.Code)
	}
	rules := fake.UserRules()
	if !slices.Equal(rules[:2], []string{"! règle saisie à la main dans AdGuard Home", "||tracker.example^"}) ||
		!slices.Contains(rules, "||graph.facebook.com^$important") || !slices.Contains(rules, "@@||mtalk.google.com^$important") {
		t.Fatalf("rules %q", rules)
	}
	if rec := e.put(c, "override", map[string]any{"domain": "google.com", "action": "block", "force": true}, true); rec.Code != http.StatusNoContent {
		t.Fatalf("forced: %d %s", rec.Code, rec.Body)
	}
	d := e.trackingGet(c, "domains", url.Values{"q": {"graph.facebook"}})["domains"].([]any)[0].(map[string]any)
	if d["override"] != "block" {
		t.Fatalf("override not shown %v", d)
	}
	for _, dom := range []string{"google.com", "graph.facebook.com", "mtalk.google.com"} {
		if rec := e.put(c, "override", map[string]any{"domain": dom, "action": "default"}, true); rec.Code != http.StatusNoContent {
			t.Fatal(rec.Code)
		}
	}
	if rules := fake.UserRules(); !slices.Equal(rules, []string{"! règle saisie à la main dans AdGuard Home", "||tracker.example^"}) {
		t.Fatalf("rules after reset %q", rules)
	}

	// Levels.
	if rec := e.put(c, "level", map[string]any{"level": "maximal"}, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown level: %d", rec.Code)
	}
	if rec := e.put(c, "level", map[string]any{"level": "strict"}, true); rec.Code != http.StatusNoContent {
		t.Fatalf("level: %d %s", rec.Code, rec.Body)
	}
	if got := fake.EnabledLists(); len(got) != 5 {
		t.Fatalf("enabled lists %v", got)
	}
	if lv := e.get(c, "/api/console/tracking/level", nil); !strings.Contains(lv.Body.String(), `"level":"strict"`) {
		t.Fatalf("level after change: %s", lv.Body)
	}
	if rec := e.put(c, "level", map[string]any{"level": "permissif"}, true); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
	if got := fake.EnabledLists(); len(got) != 1 {
		t.Fatalf("enabled lists after permissif %v", got)
	}
}

func TestTrackingIncrementalAndGaps(t *testing.T) {
	e, fake, _ := newTrackingEnv(t)
	ctx := context.Background()
	base := time.Now().Add(-3 * time.Hour)
	for i := range 1200 {
		fake.AddQuery(base.Add(time.Duration(i)*time.Second), "192.0.2.10", "s25", "app-measurement.com")
	}
	tr := e.srv.tracking
	if err := tr.refreshStatus(ctx); err != nil {
		t.Fatal(err)
	}
	// Two pages per poll (one is spent on the newest entries): the remainder is kept as a gap and read by the following polls.
	for range 5 {
		if err := tr.readLog(ctx, 2); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 700 { // new entries during the catch-up, read once they are older than the lag
		fake.AddQuery(time.Now().Add(time.Duration(i)*time.Millisecond), "192.0.2.10", "s25", "www.google.com")
	}
	e.srv.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	for range 4 {
		if err := tr.readLog(ctx, 2); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := e.st.TrackingCounts(ctx, nil, base.Add(-time.Hour).UnixMilli(), time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if counts["app-measurement.com"].Queries != 1200 || counts["app-measurement.com"].Blocked != 1200 || counts["www.google.com"].Queries != 700 {
		t.Fatalf("counts %+v", counts)
	}
	st, _ := tr.loadState(ctx)
	if len(st.Gaps) != 0 {
		t.Fatalf("gaps left %+v", st.Gaps)
	}
	// Clients: VIGIE_ADGUARD_CLIENTS restricts a device to its AdGuard clients.
	if c, _ := e.st.TrackingCounts(ctx, []string{"other"}, base.UnixMilli(), time.Now().UnixMilli()); len(c) != 0 {
		t.Fatalf("other client %v", c)
	}
}

func TestTrackingAdGuardDown(t *testing.T) {
	e, fake, ag := newTrackingEnv(t)
	c := e.session()
	e.seedTraffic(fake, time.Now().Add(-10*time.Minute))
	if err := e.srv.tracking.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	ag.Close()
	if err := e.srv.tracking.pollOnce(context.Background()); err == nil {
		t.Fatal("poll of a stopped AdGuard succeeded")
	}
	e.srv.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	sum := e.trackingGet(c, "summary", nil)
	if sum["adguard"] != false || sum["level"] != nil {
		t.Fatalf("summary with AdGuard down %v", sum)
	}
	if rec := e.put(c, "override", map[string]any{"domain": "a.example", "action": "block"}, true); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("override with AdGuard down: %d", rec.Code)
	}
	if rec := e.put(c, "level", map[string]any{"level": "strict"}, true); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("level with AdGuard down: %d", rec.Code)
	}
	if rec := e.get(c, "/api/console/devices", nil); rec.Code != http.StatusOK {
		t.Fatal("other endpoints broken")
	}
}

func TestTrackingWithoutAdGuard(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	e.seedTraffic(adguard.NewFake("", ""), time.Now().Add(-10*time.Minute))
	sum := e.trackingGet(c, "summary", nil)
	if sum["adguard"] != false || num(sum["totals"].(map[string]any)["queries"]) != 7 {
		t.Fatalf("summary %v", sum)
	}
	d := e.trackingGet(c, "domains", nil)["domains"].([]any)[0].(map[string]any)
	if d["domain"] != "app-measurement.com" || num(d["queries"]) != 3 || d["status"] != nil {
		t.Fatalf("domain %v", d)
	}
	if rec := e.put(c, "override", map[string]any{"domain": "a.example", "action": "block"}, true); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("override: %d", rec.Code)
	}
	if rec := e.put(c, "level", map[string]any{"level": "strict"}, true); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("level: %d", rec.Code)
	}
	if rec := e.get(c, "/api/console/tracking/summary", url.Values{"from": {"x"}, "to": {"y"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad dates: %d", rec.Code)
	}
	if rec := e.get(nil, "/api/console/tracking/summary", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("without session: %d", rec.Code)
	}
	_ = tracking.Other
}

// app.notification with content (contract §10) goes through the generic ingestion and is counted.
func TestNotificationContentCounted(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	at := time.Now().Add(-5 * time.Minute)
	n := func(event string, content bool) map[string]any {
		d := map[string]any{"package": "com.whatsapp", "event": event, "category": "msg", "channel": "messages", "ongoing": false, "importance": 4}
		if content {
			d["title"], d["text"], d["redacted"] = "Alice", "Ton code : ••••••", true
		}
		return e.event(at, "app.notification", 0, d)
	}
	if r := e.ingest([]map[string]any{n("posted", true), n("posted", false), n("removed", false)}); r.Accepted != 3 {
		t.Fatalf("ingest %+v", r)
	}
	rec := e.get(c, "/api/console/stats/top", url.Values{"kind": {"notification_package"}, "from": {model.FormatTS(at.Add(-time.Hour))}, "to": {model.FormatTS(time.Now())}})
	if !strings.Contains(rec.Body.String(), `{"key":"com.whatsapp","count":2}`) {
		t.Fatalf("top: %s", rec.Body)
	}
	rec = e.get(c, "/api/console/events", url.Values{"type": {"app.notification"}, "q": {"Alice"}, "from": {model.FormatTS(at.Add(-time.Hour))}, "to": {model.FormatTS(time.Now())}})
	if !strings.Contains(rec.Body.String(), `"redacted":true`) {
		t.Fatalf("events: %s", rec.Body)
	}
}
