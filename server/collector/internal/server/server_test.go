package server

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/auth"
	"github.com/erwsim/android-telemetry/server/collector/internal/config"
	"github.com/erwsim/android-telemetry/server/collector/internal/enroll"
	"github.com/erwsim/android-telemetry/server/collector/internal/model"
	"github.com/erwsim/android-telemetry/server/collector/internal/pki"
	"github.com/erwsim/android-telemetry/server/collector/internal/sim"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

type env struct {
	t   *testing.T
	cfg *config.Config
	st  *store.Store
	srv *Server
	h   http.Handler
	ca  *pki.CA
	dev *enroll.File
	fp  string
	rng *mrand.Rand
	mu  sync.Mutex
}

var testPassword = "mot-de-passe-de-test"

func newEnv(t *testing.T, vars map[string]string) *env {
	t.Helper()
	dir := t.TempDir()
	m := map[string]string{"VIGIE_DATA_DIR": dir, "VIGIE_COOKIE_SECURE": "false"}
	for k, v := range vars {
		m[k] = v
	}
	cfg, err := config.FromLookup(func(k string) (string, bool) { v, ok := m[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(dir, "vigie.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ca, _, err := pki.LoadOrCreate(filepath.Join(dir, "pki"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f, err := enroll.Create(ctx, st, ca, enroll.Params{Name: "s25", IngestURL: "https://ingest.example.org"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := pki.FingerprintPEM([]byte(f.ClientCertPEM))
	consoleFS := fstest.MapFS{
		"index.html":         {Data: []byte("<!doctype html><title>Vigie</title>")},
		"assets/app-1234.js": {Data: []byte("console.log(1)")},
	}
	srv, err := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{ConsoleFS: consoleFS})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, cfg: cfg, st: st, srv: srv, h: srv.Handler(), ca: ca, dev: f, fp: fp, rng: mrand.New(mrand.NewSource(7))}
}

type reqOpt func(*http.Request)

func withRemote(addr string) reqOpt { return func(r *http.Request) { r.RemoteAddr = addr } }
func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func withCookie(c *http.Cookie) reqOpt {
	return func(r *http.Request) {
		if c != nil {
			r.AddCookie(c)
		}
	}
}

func (e *env) do(method, path string, body io.Reader, opts ...reqOpt) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = "127.0.0.1:40000"
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *env) event(ts time.Time, typ string, sev int, data map[string]any) map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	if data == nil {
		data = map[string]any{}
	}
	return map[string]any{"id": sim.NewULID(ts, e.rng), "ts": model.FormatTS(ts), "seq": e.rng.Int63n(1 << 40), "boot_id": "boot-1",
		"elapsed_ms": 1000, "type": typ, "sev": sev, "data": data}
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func (e *env) batch(evs []map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"device_id": e.dev.DeviceID, "agent_version": "1.0.0", "sent_at": model.FormatTS(time.Now()), "events": evs})
	return b
}

func (e *env) ingestRaw(body []byte, gzipped bool, opts ...reqOpt) *httptest.ResponseRecorder {
	if gzipped {
		body = gz(body)
	}
	base := []reqOpt{
		withHeader("Authorization", "Bearer "+e.dev.DeviceToken),
		withHeader("Content-Type", "application/json"),
		withHeader(CertHeader, e.fp),
	}
	if gzipped {
		base = append(base, withHeader("Content-Encoding", "gzip"))
	}
	return e.do(http.MethodPost, "/api/v1/ingest", bytes.NewReader(body), append(base, opts...)...)
}

type ingestResp struct {
	Accepted   int         `json:"accepted"`
	Duplicates int         `json:"duplicates"`
	Rejected   []rejection `json:"rejected"`
	ServerTime string      `json:"server_time"`
}

func (e *env) ingest(evs []map[string]any) ingestResp {
	e.t.Helper()
	rec := e.ingestRaw(e.batch(evs), true)
	if rec.Code != http.StatusOK {
		e.t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	var r ingestResp
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func decodeJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

// --- ingestion ---------------------------------------------------------------

func TestIngestAcceptDuplicateReject(t *testing.T) {
	e := newEnv(t, nil)
	now := time.Now()
	good := []map[string]any{
		e.event(now.Add(-time.Minute), "location.fix", 0, map[string]any{"lat": 48.85, "lon": 2.35, "acc_m": 5}),
		e.event(now.Add(-50*time.Second), "net.dns", 0, map[string]any{"package": "com.google.android.gms", "hostname": "app-measurement.com"}),
		e.event(now.Add(-40*time.Second), "vendor.brand_new_type", 0, nil), // unknown types are accepted
	}
	r := e.ingest(good)
	if r.Accepted != 3 || r.Duplicates != 0 || len(r.Rejected) != 0 || r.ServerTime == "" {
		t.Fatalf("first batch: %+v", r)
	}
	bad := e.event(now, "Bad.Type", 0, nil)
	badSev := e.event(now, "net.dns", 7, nil)
	repeated := e.event(now, "net.connect", 0, map[string]any{"ip": "1.2.3.4", "port": 443})
	r = e.ingest([]map[string]any{good[0], good[1], bad, badSev, repeated, repeated})
	if r.Accepted != 1 || r.Duplicates != 3 || len(r.Rejected) != 2 {
		t.Fatalf("second batch: %+v", r)
	}
	if r.Accepted+r.Duplicates+len(r.Rejected) != 6 {
		t.Fatal("counts do not add up")
	}
	reasons := map[string]string{}
	for _, x := range r.Rejected {
		reasons[x.ID] = x.Reason
	}
	if reasons[bad["id"].(string)] != model.ReasonInvalidType || reasons[badSev["id"].(string)] != model.ReasonInvalidSev {
		t.Fatalf("reasons %v", reasons)
	}
	// Identity encoding works too.
	rec := e.ingestRaw(e.batch([]map[string]any{e.event(now, "device.screen", 0, map[string]any{"state": "on"})}), false)
	if rec.Code != http.StatusOK || decodeJSON[ingestResp](t, rec).Accepted != 1 {
		t.Fatalf("identity: %d %s", rec.Code, rec.Body)
	}
	// Malformed events inside a valid batch are rejected individually.
	raw := []byte(fmt.Sprintf(`{"device_id":%q,"events":[42,{"id":"x"},%s]}`, e.dev.DeviceID, mustJSON(e.event(now, "a.b", 0, nil))))
	rec = e.ingestRaw(raw, true)
	if res := decodeJSON[ingestResp](t, rec); res.Accepted != 1 || len(res.Rejected) != 2 {
		t.Fatalf("partial batch %+v", res)
	}
	dev, _ := e.st.GetDevice(context.Background(), e.dev.DeviceID)
	if dev.LastSeen == nil || dev.AgentVersion != "1.0.0" {
		t.Fatal("last_seen / agent_version not updated")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestIngestLimits(t *testing.T) {
	e := newEnv(t, nil)
	now := time.Now()
	var many []map[string]any
	for range MaxBatchEvents + 1 {
		many = append(many, e.event(now, "net.dns", 0, nil))
	}
	if rec := e.ingestRaw(e.batch(many), true); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("501 events: %d", rec.Code)
	}
	// More than 1 MiB once compressed (random data does not compress).
	noise := make([]byte, 1500<<10)
	_, _ = rand.Read(noise)
	big := e.batch([]map[string]any{e.event(now, "x.y", 0, map[string]any{"blob": fmt.Sprintf("%x", noise)})})
	if rec := e.ingestRaw(big, true); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("compressed > 1 MiB: %d", rec.Code)
	}
	// More than 8 MiB once decompressed (compresses well).
	huge := []byte(fmt.Sprintf(`{"device_id":%q,"events":[],"pad":"%s"}`, e.dev.DeviceID, strings.Repeat("a", 9<<20)))
	if rec := e.ingestRaw(huge, true); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("decompressed > 8 MiB: %d", rec.Code)
	}
	if rec := e.ingestRaw(huge, false); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("identity > 8 MiB: %d", rec.Code)
	}
	// Bad gzip, bad JSON, bad content type, missing events.
	rec := e.do(http.MethodPost, "/api/v1/ingest", strings.NewReader("not gzip"),
		withHeader("Authorization", "Bearer "+e.dev.DeviceToken), withHeader(CertHeader, e.fp),
		withHeader("Content-Type", "application/json"), withHeader("Content-Encoding", "gzip"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad gzip: %d", rec.Code)
	}
	if rec := e.ingestRaw([]byte("{"), true); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", rec.Code)
	}
	if rec := e.ingestRaw([]byte(fmt.Sprintf(`{"device_id":%q}`, e.dev.DeviceID)), true); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing events: %d", rec.Code)
	}
	if rec := e.ingestRaw(e.batch(nil), false, withHeader("Content-Type", "text/plain")); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type: %d", rec.Code)
	}
	if rec := e.ingestRaw(e.batch(nil), false, withHeader("Content-Encoding", "br")); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("encoding: %d", rec.Code)
	}
}

func TestIngestAuth(t *testing.T) {
	e := newEnv(t, nil)
	body := e.batch([]map[string]any{e.event(time.Now(), "net.dns", 0, nil)})
	other := strings.Repeat("ab", 32)
	cases := map[string][]reqOpt{
		"no token":          {withHeader("Authorization", "")},
		"basic auth":        {withHeader("Authorization", "Basic eDp5")},
		"wrong token":       {withHeader("Authorization", "Bearer "+strings.Repeat("A", 43))},
		"no cert header":    {withHeader(CertHeader, "")},
		"other certificate": {withHeader(CertHeader, other)},
		"garbage cert":      {withHeader(CertHeader, "zz")},
		// The header is ignored when the peer is not a trusted proxy.
		"untrusted proxy": {withRemote("203.0.113.9:1234")},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			rec := e.ingestRaw(body, true, opts...)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("got %d %s", rec.Code, rec.Body)
			}
		})
	}
	// Colon-separated upper-case fingerprints are accepted.
	var colon []string
	for i := 0; i < len(e.fp); i += 2 {
		colon = append(colon, strings.ToUpper(e.fp[i:i+2]))
	}
	if rec := e.ingestRaw(body, true, withHeader(CertHeader, strings.Join(colon, ":"))); rec.Code != http.StatusOK {
		t.Fatalf("colon fingerprint: %d", rec.Code)
	}
	// device_id must match the token.
	wrong := []byte(strings.Replace(string(body), e.dev.DeviceID, "dev_ffffffffffffffff", 1))
	if rec := e.ingestRaw(wrong, true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("device_id mismatch: %d", rec.Code)
	}
	// Ping.
	rec := e.do(http.MethodGet, "/api/v1/ping", nil, withHeader("Authorization", "Bearer "+e.dev.DeviceToken), withHeader(CertHeader, e.fp))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), e.dev.DeviceID) {
		t.Fatalf("ping: %d %s", rec.Code, rec.Body)
	}
	// Revocation is immediate.
	if err := e.st.RevokeDevice(context.Background(), e.dev.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if rec := e.ingestRaw(body, true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked: %d", rec.Code)
	}
}

func TestIngestWithoutRequiredCert(t *testing.T) {
	e := newEnv(t, map[string]string{"VIGIE_REQUIRE_CLIENT_CERT": "false"})
	body := e.batch([]map[string]any{e.event(time.Now(), "net.dns", 0, nil)})
	if rec := e.ingestRaw(body, true, withHeader(CertHeader, "")); rec.Code != http.StatusOK {
		t.Fatalf("no cert allowed: %d", rec.Code)
	}
	// A wrong fingerprint from a trusted proxy is still refused.
	if rec := e.ingestRaw(body, true, withHeader(CertHeader, strings.Repeat("cd", 32))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong cert: %d", rec.Code)
	}
}

func TestIngestAuthFailureRateLimit(t *testing.T) {
	e := newEnv(t, map[string]string{"VIGIE_TRUSTED_PROXIES": "10.0.0.1"})
	body := e.batch([]map[string]any{})
	bad := []reqOpt{withRemote("10.0.0.1:5000"), withHeader("X-Forwarded-For", "198.51.100.7"), withHeader("Authorization", "Bearer nope")}
	codes := map[int]int{}
	for range 12 {
		codes[e.ingestRaw(body, true, bad...).Code]++
	}
	if codes[http.StatusUnauthorized] != 10 || codes[http.StatusTooManyRequests] != 2 {
		t.Fatalf("codes %v", codes)
	}
	rec := e.ingestRaw(body, true, bad...)
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	// Another client IP behind the same proxy is not affected.
	good := []reqOpt{withRemote("10.0.0.1:5000"), withHeader("X-Forwarded-For", "198.51.100.8")}
	if rec := e.ingestRaw(body, true, good...); rec.Code != http.StatusOK {
		t.Fatalf("other IP: %d %s", rec.Code, rec.Body)
	}
}

func TestIngestDeviceRateLimit(t *testing.T) {
	e := newEnv(t, nil)
	body := e.batch([]map[string]any{})
	got429 := false
	for range 80 {
		rec := e.ingestRaw(body, true)
		if rec.Code == http.StatusTooManyRequests {
			got429 = rec.Header().Get("Retry-After") != ""
			break
		}
	}
	if !got429 {
		t.Fatal("device rate limit never reached")
	}
}

// --- console -------------------------------------------------------------------

func (e *env) addUser(name string) {
	e.t.Helper()
	h, err := auth.HashPassword(testPassword)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.st.UpsertUser(context.Background(), name, h, time.Now()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) login(name, password string, opts ...reqOpt) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"username": name, "password": password})
	return e.do(http.MethodPost, "/api/console/login", bytes.NewReader(b),
		append([]reqOpt{withHeader("X-Requested-With", "vigie"), withHeader("Content-Type", "application/json")}, opts...)...)
}

func (e *env) session() *http.Cookie {
	e.t.Helper()
	e.addUser("admin")
	rec := e.login("admin", testPassword)
	if rec.Code != http.StatusNoContent {
		e.t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "vigie_session" {
			return c
		}
	}
	e.t.Fatal("no session cookie")
	return nil
}

func (e *env) get(c *http.Cookie, path string, q url.Values) *httptest.ResponseRecorder {
	if q != nil {
		path += "?" + q.Encode()
	}
	return e.do(http.MethodGet, path, nil, withCookie(c))
}

func TestConsoleAuth(t *testing.T) {
	e := newEnv(t, nil)
	if rec := e.get(nil, "/api/console/me", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("me without session: %d", rec.Code)
	}
	if rec := e.get(nil, "/api/console/devices", nil); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"error":"unauthorized"`) {
		t.Fatalf("devices without session: %d %s", rec.Code, rec.Body)
	}
	e.addUser("admin")
	// CSRF header required on login.
	b, _ := json.Marshal(map[string]string{"username": "admin", "password": testPassword})
	if rec := e.do(http.MethodPost, "/api/console/login", bytes.NewReader(b)); rec.Code != http.StatusForbidden {
		t.Fatalf("login without X-Requested-With: %d", rec.Code)
	}
	if rec := e.login("admin", "mauvais-mot-de-passe"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", rec.Code)
	}
	if rec := e.login("nobody", testPassword); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown user: %d", rec.Code)
	}
	rec := e.login("admin", testPassword)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login: %d", rec.Code)
	}
	setCookie := rec.Header().Get("Set-Cookie")
	for _, attr := range []string{"HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(setCookie, attr) {
			t.Fatalf("cookie %q lacks %s", setCookie, attr)
		}
	}
	c := rec.Result().Cookies()[0]
	me := e.get(c, "/api/console/me", nil)
	if me.Code != http.StatusOK || decodeJSON[map[string]string](t, me)["username"] != "admin" {
		t.Fatalf("me: %d %s", me.Code, me.Body)
	}
	// Logout requires the CSRF header, then invalidates the session server-side.
	if rec := e.do(http.MethodPost, "/api/console/logout", nil, withCookie(c)); rec.Code != http.StatusForbidden {
		t.Fatalf("logout without header: %d", rec.Code)
	}
	if rec := e.do(http.MethodPost, "/api/console/logout", nil, withCookie(c), withHeader("X-Requested-With", "vigie")); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := e.get(c, "/api/console/me", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session survived logout: %d", rec.Code)
	}
}

func TestSecureCookieAttributes(t *testing.T) {
	e := newEnv(t, map[string]string{"VIGIE_COOKIE_SECURE": "true"})
	e.addUser("admin")
	rec := e.login("admin", testPassword)
	sc := rec.Header().Get("Set-Cookie")
	if !strings.HasPrefix(sc, "__Host-vigie_session=") || !strings.Contains(sc, "Secure") {
		t.Fatalf("cookie %q", sc)
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("no HSTS with secure cookies")
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t, nil)
	e.addUser("admin")
	limited := false
	for range 12 {
		if rec := e.login("admin", "mauvais-mot-de-passe"); rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("login attempts not limited")
	}
	// The correct password is refused while limited.
	if rec := e.login("admin", testPassword); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("limited login: %d", rec.Code)
	}
}

// seed ingests a known dataset and returns its time origin.
func (e *env) seed() time.Time {
	e.t.Helper()
	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Hour)
	var evs []map[string]any
	for i := range 300 {
		ts := base.Add(time.Duration(i) * 30 * time.Second)
		host := []string{"app-measurement.com", "mtalk.google.com", "api.samsungcloud.com"}[i%3]
		evs = append(evs, e.event(ts, "net.dns", 0, map[string]any{"package": "com.google.android.gms", "hostname": host, "addresses": []any{"1.2.3.4"}}))
		if i%2 == 0 {
			evs = append(evs, e.event(ts.Add(time.Millisecond), "net.connect", 0, map[string]any{"package": "com.whatsapp", "ip": "157.240.1.1", "port": 443}))
		}
		if i%10 == 0 {
			evs = append(evs, e.event(ts, "location.fix", 0, map[string]any{"lat": 48.85 + float64(i)/10000, "lon": 2.35, "acc_m": 5, "speed_mps": 1.2, "provider": "gps"}))
		}
	}
	evs = append(evs,
		e.event(base.Add(10*time.Minute), "security.ca_cert", 2, map[string]any{"event": "added", "sha256": "ab", "subject": "CN=Proxy"}),
		e.event(base.Add(20*time.Minute), "agent.tamper", 3, map[string]any{"kind": "force_stop", "detail": "x"}),
		e.event(base.Add(30*time.Minute), "security.posture", 0, map[string]any{"adb_enabled": false, "encrypted": true}),
		e.event(base.Add(90*time.Minute), "security.posture", 1, map[string]any{"adb_enabled": true, "encrypted": true}),
		e.event(base.Add(time.Minute), "agent.heartbeat", 0, map[string]any{"battery_pct": 80, "device_owner": true}),
		e.event(base.Add(2*time.Minute), "net.usage", 0, map[string]any{"from": "a", "to": "b", "apps": []any{
			map[string]any{"package": "com.spotify.music", "rx_bytes": 5000, "tx_bytes": 100},
			map[string]any{"package": "com.whatsapp", "rx_bytes": 10, "tx_bytes": 10}}}),
		e.event(base.Add(3*time.Minute), "app.foreground", 0, map[string]any{"package": "com.whatsapp", "event": "resumed"}),
		e.event(base.Add(3*time.Minute), "app.notification", 0, map[string]any{"package": "com.whatsapp", "event": "posted"}),
		e.event(base.Add(5*time.Minute), "app.inventory", 0, map[string]any{"part": 1, "parts": 2, "apps": []any{map[string]any{"package": "a"}, map[string]any{"package": "b"}}}),
		e.event(base.Add(5*time.Minute+time.Second), "app.inventory", 0, map[string]any{"part": 2, "parts": 2, "apps": []any{map[string]any{"package": "c"}}}),
	)
	for i := 0; i < len(evs); i += 500 {
		r := e.ingest(evs[i:min(i+500, len(evs))])
		if len(r.Rejected) != 0 {
			e.t.Fatalf("rejected %+v", r.Rejected)
		}
	}
	return base
}

type eventsResp struct {
	Events []struct {
		ID         string         `json:"id"`
		TS         string         `json:"ts"`
		Type       string         `json:"type"`
		Sev        int            `json:"sev"`
		DeviceID   string         `json:"device_id"`
		ReceivedAt string         `json:"received_at"`
		Data       map[string]any `json:"data"`
	} `json:"events"`
	NextCursor string `json:"next_cursor"`
}

func TestConsoleEvents(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	base := e.seed()
	rng := url.Values{"from": {model.FormatTS(base)}, "to": {model.FormatTS(base.Add(4 * time.Hour))}}
	q := func(extra map[string]string) url.Values {
		v := url.Values{}
		for k, x := range rng {
			v[k] = x
		}
		for k, x := range extra {
			v.Set(k, x)
		}
		return v
	}

	// Pagination covers everything exactly once, newest first.
	seen := map[string]bool{}
	var lastTS string
	cursor := ""
	pages := 0
	for {
		extra := map[string]string{"limit": "37"}
		if cursor != "" {
			extra["cursor"] = cursor
		}
		rec := e.get(c, "/api/console/events", q(extra))
		if rec.Code != http.StatusOK {
			t.Fatalf("events: %d %s", rec.Code, rec.Body)
		}
		r := decodeJSON[eventsResp](t, rec)
		for _, ev := range r.Events {
			if seen[ev.ID] {
				t.Fatalf("duplicate %s across pages", ev.ID)
			}
			seen[ev.ID] = true
			if lastTS != "" && ev.TS > lastTS {
				t.Fatalf("not newest first: %s after %s", ev.TS, lastTS)
			}
			lastTS = ev.TS
			if ev.ReceivedAt == "" || ev.DeviceID != e.dev.DeviceID {
				t.Fatal("missing received_at/device_id")
			}
		}
		pages++
		if r.NextCursor == "" {
			break
		}
		cursor = r.NextCursor
	}
	if len(seen) != 300+150+30+10 || pages < 10 {
		t.Fatalf("%d events over %d pages", len(seen), pages)
	}

	// Type prefixes, severity, text search, device filter.
	r := decodeJSON[eventsResp](t, e.get(c, "/api/console/events", q(map[string]string{"type": "security.,agent.tamper", "limit": "500"})))
	if len(r.Events) != 4 { // ca_cert, 2 postures, tamper
		t.Fatalf("type filter: %d", len(r.Events))
	}
	r = decodeJSON[eventsResp](t, e.get(c, "/api/console/events", q(map[string]string{"sev_min": "2"})))
	if len(r.Events) != 2 || r.Events[0].Type != "agent.tamper" {
		t.Fatalf("sev filter: %+v", r.Events)
	}
	r = decodeJSON[eventsResp](t, e.get(c, "/api/console/events", q(map[string]string{"type": "net.", "sev_min": "1"})))
	if len(r.Events) != 0 {
		t.Fatal("type+sev filter")
	}
	r = decodeJSON[eventsResp](t, e.get(c, "/api/console/events", q(map[string]string{"q": "MTALK.google", "limit": "500"})))
	if len(r.Events) != 100 {
		t.Fatalf("text search: %d", len(r.Events))
	}
	r = decodeJSON[eventsResp](t, e.get(c, "/api/console/events", q(map[string]string{"q": "100%_", "limit": "500"})))
	if len(r.Events) != 0 {
		t.Fatal("LIKE wildcards not escaped")
	}
	r = decodeJSON[eventsResp](t, e.get(c, "/api/console/events", q(map[string]string{"device_id": "dev_0000000000000000"})))
	if len(r.Events) != 0 {
		t.Fatal("device filter")
	}
	// Single event.
	one := e.get(c, "/api/console/events/"+r2id(t, e, c, q), nil)
	if one.Code != http.StatusOK || !strings.Contains(one.Body.String(), `"received_at"`) {
		t.Fatalf("event by id: %d", one.Code)
	}
	if rec := e.get(c, "/api/console/events/01JCQ8Z3K4M5N6P7Q8R9S0T1V2", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", rec.Code)
	}
	// Parameter validation.
	for _, bad := range []url.Values{
		{"to": {model.FormatTS(base)}},
		q(map[string]string{"limit": "501"}),
		q(map[string]string{"sev_min": "9"}),
		q(map[string]string{"type": "NET'"}),
		q(map[string]string{"cursor": "!!!"}),
		q(map[string]string{"from": "hier"}),
		q(map[string]string{"device_id": "x' OR 1=1"}),
	} {
		rec := e.get(c, "/api/console/events", bad)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error"`) {
			t.Fatalf("%v: %d %s", bad, rec.Code, rec.Body)
		}
	}
}

func r2id(t *testing.T, e *env, c *http.Cookie, q func(map[string]string) url.Values) string {
	r := decodeJSON[eventsResp](t, e.get(c, "/api/console/events", q(map[string]string{"limit": "1"})))
	return strings.ToLower(r.Events[0].ID)
}

func TestConsoleLocationsStatsAppsPosture(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	base := e.seed()
	rng := url.Values{"from": {model.FormatTS(base)}, "to": {model.FormatTS(base.Add(4 * time.Hour))}, "device_id": {e.dev.DeviceID}}
	with := func(k, v string) url.Values {
		x := url.Values{}
		for a, b := range rng {
			x[a] = b
		}
		x.Set(k, v)
		return x
	}

	type points struct {
		Points []struct {
			TS  string  `json:"ts"`
			Lat float64 `json:"lat"`
		} `json:"points"`
	}
	all := decodeJSON[points](t, e.get(c, "/api/console/locations", rng))
	if len(all.Points) != 30 {
		t.Fatalf("locations: %d", len(all.Points))
	}
	sub := decodeJSON[points](t, e.get(c, "/api/console/locations", with("max_points", "7")))
	if len(sub.Points) != 7 || sub.Points[0].TS != all.Points[0].TS || sub.Points[6].TS != all.Points[29].TS {
		t.Fatalf("sub-sampling: %+v", sub.Points)
	}
	for i := 1; i < len(sub.Points); i++ {
		if sub.Points[i].TS <= sub.Points[i-1].TS {
			t.Fatal("points not in chronological order")
		}
	}

	type timeline struct {
		Buckets []string `json:"buckets"`
		Series  []struct {
			Key    string  `json:"key"`
			Counts []int64 `json:"counts"`
		} `json:"series"`
	}
	tl := decodeJSON[timeline](t, e.get(c, "/api/console/stats/timeline", with("bucket", "hour")))
	if len(tl.Buckets) != 5 || tl.Series[0].Key != "net" {
		t.Fatalf("timeline: %+v", tl)
	}
	var netTotal int64
	for _, n := range tl.Series[0].Counts {
		netTotal += n
	}
	if netTotal != 300+150+1 {
		t.Fatalf("net total %d", netTotal)
	}
	tlm := decodeJSON[timeline](t, e.get(c, "/api/console/stats/timeline", with("bucket", "minute")))
	if len(tlm.Buckets) != 241 {
		t.Fatalf("minute buckets %d", len(tlm.Buckets))
	}
	var sumMin int64
	for _, s := range tlm.Series {
		for _, n := range s.Counts {
			sumMin += n
		}
	}
	if sumMin != 300+150+30+10 {
		t.Fatalf("minute total %d", sumMin)
	}
	tq := with("type", "security.,agent.tamper")
	tq.Set("by", "type")
	tlt := decodeJSON[timeline](t, e.get(c, "/api/console/stats/timeline", tq))
	if len(tlt.Series) != 3 {
		t.Fatalf("timeline type filter: %+v", tlt.Series)
	}
	tq.Set("bucket", "minute")
	if tlt = decodeJSON[timeline](t, e.get(c, "/api/console/stats/timeline", tq)); len(tlt.Series) != 3 {
		t.Fatalf("minute timeline type filter: %+v", tlt.Series)
	}
	tls := decodeJSON[timeline](t, e.get(c, "/api/console/stats/timeline", with("by", "sev")))
	if len(tls.Series) != 4 {
		t.Fatalf("by sev: %+v", tls.Series)
	}
	long := url.Values{"from": {"2020-01-01T00:00:00Z"}, "to": {"2026-01-01T00:00:00Z"}, "bucket": {"minute"}}
	if rec := e.get(c, "/api/console/stats/timeline", long); rec.Code != http.StatusBadRequest {
		t.Fatalf("too many buckets: %d", rec.Code)
	}

	type top struct {
		Items []struct {
			Key   string `json:"key"`
			Count int64  `json:"count"`
			Bytes *int64 `json:"bytes"`
		} `json:"items"`
	}
	tp := decodeJSON[top](t, e.get(c, "/api/console/stats/top", with("kind", "dns_hostname")))
	if len(tp.Items) != 3 || tp.Items[0].Count != 100 || tp.Items[0].Bytes != nil {
		t.Fatalf("top dns: %+v", tp.Items)
	}
	tp = decodeJSON[top](t, e.get(c, "/api/console/stats/top", with("kind", "connect_dest")))
	if len(tp.Items) != 1 || tp.Items[0].Key != "157.240.1.1:443" || tp.Items[0].Count != 150 {
		t.Fatalf("top connect: %+v", tp.Items)
	}
	tp = decodeJSON[top](t, e.get(c, "/api/console/stats/top", with("kind", "usage_package")))
	if len(tp.Items) != 2 || tp.Items[0].Key != "com.spotify.music" || tp.Items[0].Bytes == nil || *tp.Items[0].Bytes != 5100 {
		t.Fatalf("top usage: %+v", tp.Items)
	}
	tp = decodeJSON[top](t, e.get(c, "/api/console/stats/top", with("kind", "event_type")))
	if tp.Items[0].Key != "net.dns" || tp.Items[0].Count != 300 {
		t.Fatalf("top types: %+v", tp.Items)
	}
	for _, k := range []string{"dns_package", "connect_package", "foreground_package", "notification_package"} {
		if tp := decodeJSON[top](t, e.get(c, "/api/console/stats/top", with("kind", k))); len(tp.Items) != 1 {
			t.Fatalf("top %s: %+v", k, tp.Items)
		}
	}
	// package filter (contract §6, Précisions).
	pq := with("kind", "dns_hostname")
	pq.Set("package", "com.google.android.gms")
	if tp := decodeJSON[top](t, e.get(c, "/api/console/stats/top", pq)); len(tp.Items) != 3 {
		t.Fatalf("top dns for gms: %+v", tp.Items)
	}
	pq.Set("package", "com.whatsapp")
	if tp := decodeJSON[top](t, e.get(c, "/api/console/stats/top", pq)); len(tp.Items) != 0 {
		t.Fatalf("top dns for whatsapp: %+v", tp.Items)
	}
	pq = with("kind", "connect_dest")
	pq.Set("package", "com.whatsapp")
	if tp := decodeJSON[top](t, e.get(c, "/api/console/stats/top", pq)); len(tp.Items) != 1 || tp.Items[0].Count != 150 {
		t.Fatalf("top connect for whatsapp: %+v", tp.Items)
	}
	pq = with("kind", "usage_package")
	pq.Set("package", "com.whatsapp")
	if tp := decodeJSON[top](t, e.get(c, "/api/console/stats/top", pq)); len(tp.Items) != 1 || *tp.Items[0].Bytes != 20 || tp.Items[0].Count != 1 {
		t.Fatalf("top usage for whatsapp: %+v", tp.Items)
	}
	pq = with("kind", "event_type")
	pq.Set("package", "com.whatsapp")
	if rec := e.get(c, "/api/console/stats/top", pq); rec.Code != http.StatusBadRequest {
		t.Fatal("package with event_type accepted")
	}
	pq = with("kind", "dns_hostname")
	pq.Set("package", "a b'")
	if rec := e.get(c, "/api/console/stats/top", pq); rec.Code != http.StatusBadRequest {
		t.Fatal("bad package accepted")
	}
	if rec := e.get(c, "/api/console/stats/top", with("kind", "nope")); rec.Code != http.StatusBadRequest {
		t.Fatal("bad kind accepted")
	}

	apps := decodeJSON[struct {
		TS       string `json:"ts"`
		Complete bool   `json:"complete"`
		Apps     []any  `json:"apps"`
	}](t, e.get(c, "/api/console/apps", url.Values{"device_id": {e.dev.DeviceID}}))
	if len(apps.Apps) != 3 || !apps.Complete || apps.TS == "" {
		t.Fatalf("apps: %+v", apps)
	}
	if rec := e.get(c, "/api/console/apps", nil); rec.Code != http.StatusBadRequest {
		t.Fatal("apps without device_id")
	}

	post := decodeJSON[struct {
		Current map[string]any `json:"current"`
		Changes []struct {
			Field string `json:"field"`
			Old   any    `json:"old"`
			New   any    `json:"new"`
		} `json:"changes"`
	}](t, e.get(c, "/api/console/posture", url.Values{"device_id": {e.dev.DeviceID}}))
	if post.Current["adb_enabled"] != true || len(post.Changes) != 1 || post.Changes[0].Field != "adb_enabled" || post.Changes[0].Old != false {
		t.Fatalf("posture: %+v", post)
	}

	type devs struct {
		Devices []struct {
			DeviceID      string         `json:"device_id"`
			LastHeartbeat map[string]any `json:"last_heartbeat"`
			LastLocation  map[string]any `json:"last_location"`
			LastPosture   map[string]any `json:"last_posture"`
			Revoked       bool           `json:"revoked"`
			AgentVersion  string         `json:"agent_version"`
		} `json:"devices"`
	}
	d := decodeJSON[devs](t, e.get(c, "/api/console/devices", nil))
	if len(d.Devices) != 1 || d.Devices[0].LastHeartbeat["battery_pct"] != float64(80) || d.Devices[0].LastLocation["lat"] == nil ||
		d.Devices[0].LastPosture["adb_enabled"] != true || d.Devices[0].AgentVersion != "1.0.0" {
		t.Fatalf("devices: %+v", d)
	}
}

func TestAlerts(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	rec := e.get(c, "/api/console/alerts", url.Values{"from": {"2026-11-01T00:00:00Z"}, "to": {"2026-11-16T00:00:00Z"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"wazuh":false`) || !strings.Contains(rec.Body.String(), `"alerts":[]`) {
		t.Fatalf("not configured: %d %s", rec.Code, rec.Body)
	}

	var gotBody string
	idx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if r.URL.Path != "/wazuh-alerts-*/_search" || u != "reader" || p != "secret" {
			http.Error(w, "nope", http.StatusForbidden)
			return
		}
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = io.WriteString(w, `{"hits":{"hits":[{"_source":{"timestamp":"2026-11-15T21:45:00.412+0000",
			"rule":{"level":10,"id":"100150","description":"Vigie : traceur BLE"},
			"data":{"vigie":{"type":"net.ble_tracker","device_id":"dev_1","id":"01J","ts":"2026-11-15T21:44:59.000Z"}}}}]}}`)
	}))
	defer idx.Close()
	e2 := newEnv(t, map[string]string{"VIGIE_WAZUH_INDEXER_URL": idx.URL, "VIGIE_WAZUH_INDEXER_USER": "reader", "VIGIE_WAZUH_INDEXER_PASSWORD": "secret"})
	c2 := e2.session()
	rec = e2.get(c2, "/api/console/alerts", url.Values{"from": {"2026-11-01T00:00:00Z"}, "to": {"2026-11-16T00:00:00Z"}, "level_min": {"7"}, "limit": {"10"}})
	ans := decodeJSON[AlertsAnswer](t, rec)
	if !ans.Wazuh || len(ans.Alerts) != 1 || ans.Alerts[0].Level != 10 || ans.Alerts[0].Type != "net.ble_tracker" ||
		ans.Alerts[0].TS != "2026-11-15T21:45:00.412Z" || ans.Alerts[0].RuleID != "100150" {
		t.Fatalf("alerts: %s", rec.Body)
	}
	if !strings.Contains(gotBody, `"data.vigie.type"`) || !strings.Contains(gotBody, `"gte":7`) || !strings.Contains(gotBody, `"size":10`) {
		t.Fatalf("query: %s", gotBody)
	}

	idx.Close()
	rec = e2.get(c2, "/api/console/alerts", nil)
	if !strings.Contains(rec.Body.String(), `"wazuh":false`) {
		t.Fatalf("unreachable: %s", rec.Body)
	}
}

func TestStream(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	ts := httptest.NewServer(e.h)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/console/stream?device_id="+e.dev.DeviceID, nil)
	req.AddCookie(c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	ev := e.event(time.Now(), "net.ble_tracker", 2, map[string]any{"address": "aa", "kind": "airtag"})
	go func() {
		time.Sleep(100 * time.Millisecond)
		body := gz(e.batch([]map[string]any{ev}))
		r, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ingest", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+e.dev.DeviceToken)
		r.Header.Set(CertHeader, e.fp)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Content-Encoding", "gzip")
		if res, err := http.DefaultClient.Do(r); err == nil {
			res.Body.Close()
		}
	}()
	sc := bufio.NewScanner(resp.Body)
	deadline := time.AfterFunc(5*time.Second, func() { resp.Body.Close() })
	defer deadline.Stop()
	for sc.Scan() {
		line := sc.Text()
		if data, ok := strings.CutPrefix(line, "data: "); ok {
			var got map[string]any
			if err := json.Unmarshal([]byte(data), &got); err != nil {
				t.Fatal(err)
			}
			if got["id"] != ev["id"] || got["type"] != "net.ble_tracker" {
				t.Fatalf("stream event %v", got)
			}
			return
		}
	}
	t.Fatal("no event received on the stream")
}

func TestStreamRequiresSession(t *testing.T) {
	e := newEnv(t, nil)
	if rec := e.get(nil, "/api/console/stream", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stream without session: %d", rec.Code)
	}
}

func TestTileURL(t *testing.T) {
	e := newEnv(t, map[string]string{"VIGIE_TILE_URL": "https://{s}.tiles.example.org/carte/{z}/{x}/{y}.png"})
	rec := e.do(http.MethodGet, "/", nil)
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "connect-src 'self' https://*.tiles.example.org;") {
		t.Fatalf("CSP %q", rec.Header().Get("Content-Security-Policy"))
	}
	if b := e.do(http.MethodGet, "/config.json", nil).Body.String(); !strings.Contains(b, `"tileUrl":"https://{s}.tiles.example.org/carte/{z}/{x}/{y}.png"`) {
		t.Fatalf("config.json %s", b)
	}
}

func TestStaticAndHeaders(t *testing.T) {
	e := newEnv(t, nil)
	rec := e.do(http.MethodGet, "/", nil)
	csp := rec.Header().Get("Content-Security-Policy")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>Vigie") {
		t.Fatalf("index: %d", rec.Code)
	}
	// Exact header of contract §6 "Précisions".
	want := "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://tile.openstreetmap.org; worker-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	if csp != want {
		t.Fatalf("CSP %q", csp)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("security headers")
	}
	// SPA fallback for client routes, 404 for missing assets.
	if rec := e.do(http.MethodGet, "/carte/jour", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>Vigie") {
		t.Fatalf("SPA fallback: %d", rec.Code)
	}
	if rec := e.do(http.MethodGet, "/assets/missing.js", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("missing asset: %d", rec.Code)
	}
	a := e.do(http.MethodGet, "/assets/app-1234.js", nil)
	if a.Code != http.StatusOK || !strings.Contains(a.Header().Get("Cache-Control"), "immutable") ||
		!strings.HasPrefix(a.Header().Get("Content-Type"), "text/javascript") {
		t.Fatalf("asset: %d %s %s", a.Code, a.Header().Get("Cache-Control"), a.Header().Get("Content-Type"))
	}
	cfgJSON := e.do(http.MethodGet, "/config.json", nil)
	if cfgJSON.Code != http.StatusOK || strings.TrimSpace(cfgJSON.Body.String()) != `{"tileUrl":"https://tile.openstreetmap.org/{z}/{x}/{y}.png"}` {
		t.Fatalf("config.json: %d %s", cfgJSON.Code, cfgJSON.Body)
	}
	if rec := e.do(http.MethodGet, "/../../etc/passwd", nil); rec.Code == http.StatusOK && !strings.Contains(rec.Body.String(), "<title>Vigie") {
		t.Fatal("path traversal")
	}
	if rec := e.do(http.MethodPost, "/", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /: %d", rec.Code)
	}
	if rec := e.do(http.MethodGet, "/api/console/nope", nil); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"error":"not_found"`) {
		t.Fatalf("unknown API: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(http.MethodGet, "/healthz", nil); rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("healthz: %d", rec.Code)
	}
	// Nothing but the closed list of commands (contract §8) goes to the agent: no configuration nor policy.
	for _, p := range []string{"/api/v1/config", "/api/v1/policy", "/api/v1/settings"} {
		if rec := e.do(http.MethodGet, p, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", p, rec.Code)
		}
	}
	for _, p := range []string{"/api/v1/commands", "/api/v1/commands/stream"} {
		if rec := e.do(http.MethodGet, p, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without credentials: %d", p, rec.Code)
		}
	}
}

func TestRetentionPurge(t *testing.T) {
	e := newEnv(t, nil)
	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)
	// Events older than the retention window are acknowledged but not stored (see TestLateEvents):
	// disable that check here to exercise the purge itself.
	e.st.SetRetention(0)
	r := e.ingest([]map[string]any{
		e.event(old, "location.fix", 0, map[string]any{"lat": 1.0, "lon": 1.0}),
		e.event(old, "net.dns", 0, map[string]any{"hostname": "x"}),
		e.event(now, "net.dns", 0, map[string]any{"hostname": "y"}),
	})
	if r.Accepted != 3 {
		t.Fatalf("%+v", r)
	}
	res, err := e.st.Purge(context.Background(), now.Add(-90*24*time.Hour), now, sessionIdle)
	if err != nil || res.Events != 2 {
		t.Fatalf("purge: %+v %v", res, err)
	}
	pts, _ := e.st.Locations(context.Background(), "", 0, now.UnixMilli()+1, 100)
	if len(pts) != 0 {
		t.Fatal("derived locations not purged")
	}
	items, _ := e.st.StatsTop(context.Background(), "", store.TopDNSHostname, "", 0, now.UnixMilli()+1, 10)
	if len(items) != 1 || items[0].Key != "y" {
		t.Fatalf("aggregates not purged: %+v", items)
	}
}

func TestSessionIdleExpiry(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	if rec := e.get(c, "/api/console/me", nil); rec.Code != http.StatusOK {
		t.Fatalf("fresh session: %d", rec.Code)
	}
	start := time.Now()
	e.srv.now = func() time.Time { return start.Add(11 * time.Hour) }
	if rec := e.get(c, "/api/console/me", nil); rec.Code != http.StatusOK {
		t.Fatalf("11 h idle: %d", rec.Code) // activity refreshes last_seen
	}
	e.srv.now = func() time.Time { return start.Add(11*time.Hour + 12*time.Hour + time.Minute) }
	if rec := e.get(c, "/api/console/me", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("12 h idle: %d", rec.Code)
	}
}

// Events relevé after the fact arrive with an old ts: they are accepted down to the retention window,
// counted by data.count in /stats/top, and an event older than the retention is acknowledged without
// being stored (accepted + duplicates + rejected still totals the batch).
func TestLateEvents(t *testing.T) {
	e := newEnv(t, map[string]string{"VIGIE_RETENTION_DAYS": "30"})
	e.addUser("admin")
	c := e.session()
	now := time.Now().UTC()
	late := now.Add(-5 * time.Hour).Truncate(time.Minute)
	days := now.Add(-20 * 24 * time.Hour)
	tooOld := now.Add(-31 * 24 * time.Hour)
	r := e.ingest([]map[string]any{
		e.event(late, "net.dns", 0, map[string]any{"package": "p", "hostname": "a.example", "count": 40, "last_event_ts": model.FormatTS(late.Add(time.Minute))}),
		e.event(late.Add(time.Second), "net.dns", 0, map[string]any{"package": "p", "hostname": "b.example"}),
		e.event(days, "net.dns", 0, map[string]any{"package": "p", "hostname": "b.example", "count": 2}),
		e.event(late, "security.log", 1, map[string]any{"tag": "x", "level": "warning", "pre_reboot": true, "count": 3}),
		e.event(tooOld, "net.dns", 0, map[string]any{"package": "p", "hostname": "gone.example", "count": 500}),
		e.event(now.Add(48*time.Hour), "net.dns", 0, map[string]any{}), // rejected: ts too far in the future
	})
	if r.Accepted != 5 || r.Duplicates != 0 || len(r.Rejected) != 1 {
		t.Fatalf("%+v", r)
	}
	type top struct {
		Items []struct {
			Key   string `json:"key"`
			Count int64  `json:"count"`
		} `json:"items"`
	}
	from, to := now.Add(-25*24*time.Hour), now
	q := url.Values{"kind": {"dns_hostname"}, "from": {model.FormatTS(from)}, "to": {model.FormatTS(to)}}
	tp := decodeJSON[top](t, e.get(c, "/api/console/stats/top", q))
	if len(tp.Items) != 2 || tp.Items[0].Key != "a.example" || tp.Items[0].Count != 40 || tp.Items[1].Key != "b.example" || tp.Items[1].Count != 3 {
		t.Fatalf("top: %+v", tp.Items)
	}
	// The recent window only holds the late events of the last hours.
	q.Set("from", model.FormatTS(now.Add(-6*time.Hour)))
	tp = decodeJSON[top](t, e.get(c, "/api/console/stats/top", q))
	if len(tp.Items) != 2 || tp.Items[1].Count != 1 {
		t.Fatalf("recent top: %+v", tp.Items)
	}
	// The timeline counts events, not occurrences.
	tl := decodeJSON[struct {
		Series []struct {
			Key    string  `json:"key"`
			Counts []int64 `json:"counts"`
		} `json:"series"`
	}](t, e.get(c, "/api/console/stats/timeline", url.Values{"from": {model.FormatTS(now.Add(-6 * time.Hour))}, "to": {model.FormatTS(now)}, "bucket": {"hour"}, "by": {"type"}}))
	total := map[string]int64{}
	for _, s := range tl.Series {
		for _, n := range s.Counts {
			total[s.Key] += n
		}
	}
	if total["net.dns"] != 2 || total["security.log"] != 1 {
		t.Fatalf("timeline: %+v", total)
	}
	// Same event resent: duplicate. The expired one is acknowledged again, never stored.
	r = e.ingest([]map[string]any{e.event(tooOld, "net.dns", 0, map[string]any{"hostname": "gone.example"})})
	if r.Accepted != 1 {
		t.Fatalf("%+v", r)
	}
	if n := e.get(c, "/api/console/events", url.Values{"from": {model.FormatTS(tooOld.Add(-time.Hour))}, "to": {model.FormatTS(now)}, "type": {"net.dns"}, "limit": {"100"}}); n.Code != http.StatusOK {
		t.Fatalf("events: %d %s", n.Code, n.Body)
	} else if strings.Contains(n.Body.String(), "gone.example") {
		t.Fatal("expired event stored")
	}
}
