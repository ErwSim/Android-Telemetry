package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/adguard"
	"github.com/erwsim/watchpost/server/collector/internal/enroll"
	"github.com/erwsim/watchpost/server/collector/internal/model"
	"github.com/erwsim/watchpost/server/collector/internal/tracking"
)

const exampleLevels = "../../examples/adguard-levels.example.json"

func newTrackingEnv(t *testing.T) (*env, *adguard.Fake, *httptest.Server) {
	t.Helper()
	fake := adguard.NewFake("watchpost", "secret-adguard")
	ag := httptest.NewServer(fake)
	t.Cleanup(ag.Close)
	e := newEnv(t, map[string]string{
		"WATCHPOST_ADGUARD_URL": ag.URL, "WATCHPOST_ADGUARD_USER": "watchpost", "WATCHPOST_ADGUARD_PASSWORD": "secret-adguard",
		"WATCHPOST_ADGUARD_LEVELS_FILE": exampleLevels, "WATCHPOST_PUBLIC_INGEST_URL": "https://ingest.watchpost.example",
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
		opts = append(opts, withHeader("X-Requested-With", "watchpost"))
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
		dns("com.dailynews.reader", "app-measurement.com", 3),
		dns("com.dailynews.reader", "apps.dailynews.example", 1),
		dns("com.google.android.gms", "mtalk.google.com", 2),
		dns("com.instagram.android", "graph.facebook.com", 1),
		e.event(at, "net.usage", 0, map[string]any{"from": model.FormatTS(at.Add(-time.Hour)), "to": model.FormatTS(at), "apps": []map[string]any{
			{"package": "com.dailynews.reader", "uid": 10255, "rx_bytes": 8000, "tx_bytes": 800, "transport": "wifi"},
			{"package": "com.spotify.music", "uid": 10254, "rx_bytes": 90000, "tx_bytes": 1000, "transport": "wifi"},
		}}),
	})
	for i := range 3 {
		fake.AddQuery(at.Add(time.Duration(i)*time.Second), "192.0.2.10", "phone", "app-measurement.com")
	}
	fake.AddQuery(at, "192.0.2.10", "phone", "apps.dailynews.example")
	fake.AddQuery(at, "192.0.2.10", "phone", "mtalk.google.com")
	fake.AddQuery(at, "192.0.2.10", "phone", "mtalk.google.com")
	fake.AddQuery(at, "192.0.2.10", "phone", "graph.facebook.com")
	fake.AddQuery(at, "192.0.2.10", "phone", "tracker.example") // blocked by the hand rule
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
	if sum["adguard"] != true || sum["level"] != "permissive" || num(tot["queries"]) != 8 || num(tot["blocked"]) != 4 || num(tot["allowed"]) != 4 {
		t.Fatalf("summary %v", sum)
	}
	if levels := sum["levels"].([]any); len(levels) != 3 || levels[1].(map[string]any)["key"] != "balanced" {
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
	if first["domain"] != "app-measurement.com" || first["status"] != "blocked" || first["reason"] != "List: AdGuard DNS filter" ||
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
	if !slices.Equal(all, []string{"app-measurement.com", "mtalk.google.com", "apps.dailynews.example", "graph.facebook.com", "tracker.example"}) {
		t.Fatalf("paginated %v", all)
	}
	if hand := e.trackingGet(c, "domains", url.Values{"q": {"tracker"}})["domains"].([]any); len(hand) != 1 ||
		!strings.HasPrefix(hand[0].(map[string]any)["reason"].(string), "Custom rule") {
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
	if lm["package"] != "com.dailynews.reader" || num(lm["queries"]) != 4 || num(lm["blocked"]) != 3 || num(lm["allowed"]) != 1 ||
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
	if !slices.Equal(rules[:2], []string{"! rule entered by hand in AdGuard Home", "||tracker.example^"}) ||
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
	// AdGuard applies the rule: the next query is blocked by "Manual block (Watchpost)".
	fake.AddQuery(time.Now(), "192.0.2.10", "phone", "graph.facebook.com")
	e.srv.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if err := e.srv.tracking.pollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	e.srv.now = time.Now
	d = e.trackingGet(c, "domains", url.Values{"q": {"graph.facebook"}, "to": {model.FormatTS(time.Now().Add(time.Hour))}})["domains"].([]any)[0].(map[string]any)
	if d["status"] != "mixed" || d["reason"] != "Manual block (Watchpost)" || num(d["blocked"]) != 1 {
		t.Fatalf("after override %v", d)
	}
	for _, dom := range []string{"google.com", "graph.facebook.com", "mtalk.google.com"} {
		if rec := e.put(c, "override", map[string]any{"domain": dom, "action": "default"}, true); rec.Code != http.StatusNoContent {
			t.Fatal(rec.Code)
		}
	}
	if rules := fake.UserRules(); !slices.Equal(rules, []string{"! rule entered by hand in AdGuard Home", "||tracker.example^"}) {
		t.Fatalf("rules after reset %q", rules)
	}

	// Levels.
	if rec := e.put(c, "level", map[string]any{"level": "maximal"}, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown level: %d", rec.Code)
	}
	if rec := e.put(c, "level", map[string]any{"level": "strict"}, true); rec.Code != http.StatusNoContent {
		t.Fatalf("level: %d %s", rec.Code, rec.Body)
	}
	if got := fake.EnabledLists(); len(got) != 6 { // with the threat list, enabled at every level
		t.Fatalf("enabled lists %v", got)
	}
	if lv := e.get(c, "/api/console/tracking/level", nil); !strings.Contains(lv.Body.String(), `"level":"strict"`) {
		t.Fatalf("level after change: %s", lv.Body)
	}
	if rec := e.put(c, "level", map[string]any{"level": "permissive"}, true); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
	if got := fake.EnabledLists(); len(got) != 2 {
		t.Fatalf("enabled lists after permissive %v", got)
	}
}

func TestTrackingIncrementalAndGaps(t *testing.T) {
	e, fake, _ := newTrackingEnv(t)
	ctx := context.Background()
	base := time.Now().Add(-3 * time.Hour)
	for i := range 1200 {
		fake.AddQuery(base.Add(time.Duration(i)*time.Second), "192.0.2.10", "phone", "app-measurement.com")
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
		fake.AddQuery(time.Now().Add(time.Duration(i)*time.Millisecond), "192.0.2.10", "phone", "www.google.com")
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
	// Clients: WATCHPOST_ADGUARD_CLIENTS restricts a device to its AdGuard clients.
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
			d["title"], d["text"], d["redacted"] = "Alice", "Your code: ••••••", true
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

// counted returns the number of queries of the tracking aggregates.
func (e *env) counted(ctx context.Context) int64 {
	e.t.Helper()
	counts, err := e.st.TrackingCounts(ctx, nil, time.Now().Add(-72*time.Hour).UnixMilli(), time.Now().Add(72*time.Hour).UnixMilli())
	if err != nil {
		e.t.Fatal(err)
	}
	var n int64
	for _, c := range counts {
		n += c.Queries
	}
	return n
}

// The query log is read like a real AdGuard Home serves it (the fake reproduces its handling of older_than,
// see adguard.Fake.search): whatever the moment of the polls, every entry is counted exactly once — never
// one missing because the poll time fell between two records or after the newest one, never one twice.
// After each complete poll the aggregates hold exactly the entries older than the reading lag.
func TestTrackingCountsEveryEntryExactlyOnce(t *testing.T) {
	e, fake, _ := newTrackingEnv(t)
	ctx := context.Background()
	tr := e.srv.tracking
	if err := tr.refreshStatus(ctx); err != nil {
		t.Fatal(err)
	}
	clock := time.Now().Add(-6 * time.Hour)
	e.srv.now = func() time.Time { return clock }
	var times []time.Time
	add := func(n int, step time.Duration) {
		for range n {
			clock = clock.Add(step)
			fake.AddQuery(clock, "192.0.2.10", "phone", "app-measurement.com")
			times = append(times, clock)
		}
	}
	eligible := func() int64 {
		var n int64
		for _, ts := range times {
			if !ts.After(clock.Add(-agLag)) {
				n++
			}
		}
		return n
	}
	poll := func(what string) {
		t.Helper()
		if err := tr.readLog(ctx, agPagesPerPoll); err != nil {
			t.Fatal(err)
		}
		if got, want := e.counted(ctx), eligible(); got != want {
			t.Fatalf("%s: %d entries counted, %d are older than the lag", what, got, want)
		}
	}
	poll("empty log")
	// A phone's ordinary traffic: a few queries, a poll every 20 s falling anywhere between them.
	for round := range 40 {
		add(1+round%5, 1700*time.Millisecond)
		clock = clock.Add(20 * time.Second)
		poll("steady traffic")
		clock = clock.Add(time.Duration(round) * 333 * time.Millisecond)
		poll("poll without anything new")
	}
	// A poll at the very nanosecond of a record, and one a nanosecond later.
	add(3, time.Second)
	clock = clock.Add(agLag)
	poll("poll at the time of the newest record")
	clock = clock.Add(time.Nanosecond)
	poll("one nanosecond later")
	// A burst of more than two pages between two polls, then the log file is rotated, twice.
	add(1234, 15*time.Millisecond)
	clock = clock.Add(2 * time.Minute)
	poll("burst of 1234")
	fake.Rotate()
	add(40, time.Second)
	clock = clock.Add(90 * time.Second)
	poll("after a rotation")
	add(700, 10*time.Millisecond)
	fake.Rotate()
	add(30, time.Second)
	clock = clock.Add(3 * time.Minute)
	poll("after a second rotation, 730 entries across the two files")
	// Records still in AdGuard Home's memory buffer (querylog.size_memory > 1).
	fake.SetMemory(50)
	add(120, 500*time.Millisecond)
	clock = clock.Add(2 * time.Minute)
	poll("with a memory buffer")
	if got := e.counted(ctx); got != int64(len(times)) {
		t.Fatalf("%d entries counted, %d made", got, len(times))
	}
	if st, _ := tr.loadState(ctx); len(st.Gaps) != 0 {
		t.Fatalf("gaps left: %+v", st.Gaps)
	}
}

// A long backlog read a page at a time, with the collector restarted between the polls, the log rotated
// meanwhile and new traffic arriving: nothing is lost, nothing is counted twice.
func TestTrackingBacklogSurvivesRestartsAndRotation(t *testing.T) {
	e, fake, _ := newTrackingEnv(t)
	ctx := context.Background()
	clock := time.Now().Add(-6 * time.Hour)
	now := func() time.Time { return clock }
	var made int64
	add := func(n int, step time.Duration, domain string) {
		for range n {
			clock = clock.Add(step)
			fake.AddQuery(clock, "192.0.2.10", "phone", domain)
			made++
		}
	}
	restart := func() *trackingService {
		t.Helper()
		srv, err := New(e.cfg, e.st, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
		if err != nil {
			t.Fatal(err)
		}
		srv.now = now
		if err := srv.tracking.refreshStatus(ctx); err != nil {
			t.Fatal(err)
		}
		return srv.tracking
	}
	add(3210, 200*time.Millisecond, "app-measurement.com") // seven pages
	clock = clock.Add(5 * time.Minute)
	prev := int64(0)
	for i := range 60 {
		tr := restart()
		if err := tr.readLog(ctx, 2); err != nil { // one page for what is new, one for the backlog
			t.Fatal(err)
		}
		got := e.counted(ctx)
		if got < prev || got > made {
			t.Fatalf("poll %d: %d entries counted after %d, %d made", i, got, prev, made)
		}
		prev = got
		switch i {
		case 2:
			fake.Rotate() // everything made so far is now in the rotated file
		case 3, 5, 7:
			add(150, 100*time.Millisecond, "www.google.com")
			clock = clock.Add(2 * time.Minute)
		}
		clock = clock.Add(7 * time.Second)
	}
	clock = clock.Add(2 * time.Minute)
	if err := restart().readLog(ctx, agPagesPerPoll); err != nil {
		t.Fatal(err)
	}
	if got := e.counted(ctx); got != made {
		t.Fatalf("%d entries counted, %d made", got, made)
	}
	if st, _ := restart().loadState(ctx); len(st.Gaps) != 0 {
		t.Fatalf("gaps left: %+v", st.Gaps)
	}
}

// The record used as a cursor is no longer in AdGuard Home's files when the reading resumes (it was only
// in memory, or the file was rewritten): AdGuard Home then finds nothing at all for that cursor. The
// records read just before it are tried, and the rest of the range is read. When the rest of the log is
// really gone (rotated away), the range ends without looping.
func TestTrackingCursorNoLongerInTheLog(t *testing.T) {
	e, fake, _ := newTrackingEnv(t)
	ctx := context.Background()
	tr := e.srv.tracking
	if err := tr.refreshStatus(ctx); err != nil {
		t.Fatal(err)
	}
	clock := time.Now().Add(-6 * time.Hour)
	e.srv.now = func() time.Time { return clock }
	for range 1700 {
		clock = clock.Add(100 * time.Millisecond)
		fake.AddQuery(clock, "192.0.2.10", "phone", "app-measurement.com")
	}
	clock = clock.Add(5 * time.Minute)
	if err := tr.readLog(ctx, 1); err != nil { // the newest page only
		t.Fatal(err)
	}
	st, _ := tr.loadState(ctx)
	if len(st.Gaps) != 1 || st.Gaps[0].Hi == "" || len(st.Gaps[0].Alt) != agAltCursors {
		t.Fatalf("state after one page: %+v", st)
	}
	cursor, _ := time.Parse(time.RFC3339Nano, st.Gaps[0].Hi)
	if !fake.Forget(cursor) {
		t.Fatal("cursor record not in the fake")
	}
	for range 4 {
		if err := tr.readLog(ctx, 2); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.counted(ctx); got != 1700 { // the forgotten record had been counted with the first page
		t.Fatalf("%d entries counted, want 1700", got)
	}
	if st, _ := tr.loadState(ctx); len(st.Gaps) != 0 {
		t.Fatalf("gaps left: %+v", st.Gaps)
	}

	// Same start on a new log, but this time the rest of the log is deleted by two rotations.
	e2, fake2, _ := newTrackingEnv(t)
	tr2 := e2.srv.tracking
	if err := tr2.refreshStatus(ctx); err != nil {
		t.Fatal(err)
	}
	e2.srv.now = func() time.Time { return clock }
	at := clock.Add(-30 * time.Minute)
	for range 1700 {
		at = at.Add(100 * time.Millisecond)
		fake2.AddQuery(at, "192.0.2.10", "phone", "app-measurement.com")
	}
	if err := tr2.readLog(ctx, 1); err != nil {
		t.Fatal(err)
	}
	fake2.Rotate()
	fake2.Rotate()
	before := fake2.Requests("/control/querylog")
	if err := tr2.readLog(ctx, agPagesPerPoll); err != nil {
		t.Fatal(err)
	}
	if got := e2.counted(ctx); got != 500 {
		t.Fatalf("%d entries counted, want the 500 read before the rotations", got)
	}
	if st, _ := tr2.loadState(ctx); len(st.Gaps) != 0 {
		t.Fatalf("gaps left: %+v", st.Gaps)
	}
	if n := fake2.Requests("/control/querylog") - before; n > 2+agAltCursors+1 {
		t.Fatalf("%d requests to conclude that the log ends", n)
	}
}

// Changes made in AdGuard Home from the console are events produced by the collector (source "server"),
// so that Wazuh can alert when the blocking is weakened — what someone holding the console session would do.
func TestTrackingChangesAreServerEvents(t *testing.T) {
	e, _, _ := newTrackingEnv(t)
	c := e.session()
	ctx := context.Background()
	if err := e.srv.tracking.pollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	other, err := enroll.Create(ctx, e.st, e.ca, enroll.Params{Name: "revoked", IngestURL: "https://ingest.watchpost.example"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.RevokeDevice(ctx, other.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	put := func(path string, body map[string]any, want int) {
		t.Helper()
		if rec := e.put(c, path, body, true); rec.Code != want {
			t.Fatalf("%s %v: %d %s", path, body, rec.Code, rec.Body)
		}
	}
	put("override", map[string]any{"domain": "tracker.example.net", "action": "block"}, http.StatusNoContent)
	put("override", map[string]any{"domain": "tracker.example.net", "action": "block"}, http.StatusNoContent) // nothing changes: no event
	put("override", map[string]any{"domain": "app-measurement.com", "action": "allow"}, http.StatusNoContent)
	put("override", map[string]any{"domain": "google.com", "action": "block"}, http.StatusConflict) // refused: no event
	put("override", map[string]any{"domain": "google.com", "action": "block", "force": true}, http.StatusNoContent)
	put("override", map[string]any{"domain": "tracker.example.net", "action": "default"}, http.StatusNoContent)
	put("level", map[string]any{"level": "permissive"}, http.StatusNoContent) // already the level: no event
	put("level", map[string]any{"level": "strict"}, http.StatusNoContent)
	put("level", map[string]any{"level": "balanced"}, http.StatusNoContent)

	type want struct {
		sev  float64
		data map[string]any
	}
	check := func(typ string, wants []want) {
		t.Helper()
		evs := e.serverEvents(c, typ) // newest first
		if len(evs) != len(wants) {
			t.Fatalf("%s: %d events, want %d: %v", typ, len(evs), len(wants), evs)
		}
		for i, w := range wants {
			ev := evs[len(evs)-1-i]
			if ev["source"] != "server" || ev["device_id"] != e.dev.DeviceID || ev["sev"] != w.sev {
				t.Fatalf("%s #%d: %v", typ, i, ev)
			}
			d := ev["data"].(map[string]any)
			if d["user"] != "admin" {
				t.Fatalf("%s #%d: user %v", typ, i, d)
			}
			for k, v := range w.data {
				if d[k] != v {
					t.Fatalf("%s #%d: %s = %v, want %v (%v)", typ, i, k, d[k], v, d)
				}
			}
			if _, has := d["previous"]; has != (w.data["previous"] != nil) {
				t.Fatalf("%s #%d: previous in %v", typ, i, d)
			}
		}
	}
	check("tracking.override", []want{
		{1, map[string]any{"domain": "tracker.example.net", "action": "block", "forced": false}},
		{2, map[string]any{"domain": "app-measurement.com", "action": "allow", "forced": false}}, // blocking weakened
		{2, map[string]any{"domain": "google.com", "action": "block", "forced": true}},           // essential domain blocked
		{2, map[string]any{"domain": "tracker.example.net", "action": "default", "forced": false, "previous": "block"}},
	})
	check("tracking.level_changed", []want{
		{1, map[string]any{"old": "permissive", "new": "strict"}},
		{2, map[string]any{"old": "strict", "new": "balanced"}}, // blocking weakened
	})
}
