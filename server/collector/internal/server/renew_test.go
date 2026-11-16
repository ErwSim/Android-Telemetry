package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/enroll"
	"github.com/erwsim/android-telemetry/server/collector/internal/pki"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

// pair is one credential generation as an agent presents it.
type pair struct{ token, fp string }

func pairOf(t *testing.T, f *enroll.File) pair {
	t.Helper()
	fp, err := pki.FingerprintPEM([]byte(f.ClientCertPEM))
	if err != nil {
		t.Fatal(err)
	}
	return pair{f.DeviceToken, fp}
}

func (e *env) renew() *enroll.File {
	e.t.Helper()
	f, err := enroll.Renew(context.Background(), e.st, e.ca, e.dev.DeviceID, enroll.Params{IngestURL: "https://ingest.example.org"}, time.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return f
}

var xffCounter int

// freshIP gives each request its own client address (X-Forwarded-For, trusted proxy), so that the
// authentication-failure limiter, tested elsewhere, does not interfere with these scenarios.
func freshIP() reqOpt {
	xffCounter++
	return withHeader("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", xffCounter%250+1))
}

// sendIngest posts one event with an arbitrary token and certificate fingerprint; returns the status.
func (e *env) sendIngest(p pair, evType string) int {
	body := e.batch([]map[string]any{e.event(time.Now(), evType, 0, nil)})
	return e.do(http.MethodPost, "/api/v1/ingest", bytes.NewReader(body),
		withHeader("Authorization", "Bearer "+p.token), withHeader("Content-Type", "application/json"), withHeader(CertHeader, p.fp), freshIP()).Code
}

func (e *env) sendPing(p pair) int {
	return e.do(http.MethodGet, "/api/v1/ping", nil, withHeader("Authorization", "Bearer "+p.token), withHeader(CertHeader, p.fp), freshIP()).Code
}

func (e *env) pending() bool {
	d, err := e.st.GetDevice(context.Background(), e.dev.DeviceID)
	if err != nil {
		e.t.Fatal(err)
	}
	return d.HasPending()
}

func (e *env) eventCount(devID string) int {
	e.t.Helper()
	page, _, err := e.st.QueryEvents(context.Background(), store.EventQuery{DeviceID: devID, ToMS: 1 << 60, Limit: 1000})
	if err != nil {
		e.t.Fatal(err)
	}
	return len(page)
}

func TestRenewalSwitchoverOnIngest(t *testing.T) {
	e := newEnv(t, nil)
	oldP := pair{e.dev.DeviceToken, e.fp}
	if c := e.sendIngest(oldP, "net.dns"); c != 200 {
		t.Fatalf("old before renewal: %d", c)
	}
	newP := pairOf(t, e.renew())
	if newP.token == oldP.token || newP.fp == oldP.fp {
		t.Fatal("renewal reused credentials")
	}
	// Before the first use of the new pair, the old one still works, and the pair is never mixed.
	if c := e.sendIngest(oldP, "net.dns"); c != 200 {
		t.Fatalf("old while pending: %d", c)
	}
	if !e.pending() {
		t.Fatal("old pair use consumed the renewal")
	}
	for name, p := range map[string]pair{
		"old token + new cert": {oldP.token, newP.fp},
		"new token + old cert": {newP.token, oldP.fp},
		"new token + no cert":  {newP.token, ""},
		"new token + bad cert": {newP.token, strings.Repeat("ab", 32)},
	} {
		if c := e.sendIngest(p, "net.dns"); c != 401 {
			t.Fatalf("%s: %d", name, c)
		}
		if c := e.sendPing(p); c != 401 {
			t.Fatalf("%s (ping): %d", name, c)
		}
	}
	if !e.pending() {
		t.Fatal("a refused mix switched the pair")
	}
	// A body whose device_id is wrong is not an authenticated send: no switch.
	wrong := []byte(strings.Replace(string(e.batch(nil)), e.dev.DeviceID, "dev_ffffffffffffffff", 1))
	if c := e.do(http.MethodPost, "/api/v1/ingest", bytes.NewReader(wrong), withHeader("Authorization", "Bearer "+newP.token),
		withHeader("Content-Type", "application/json"), withHeader(CertHeader, newP.fp)).Code; c != 401 {
		t.Fatalf("wrong device_id: %d", c)
	}
	if !e.pending() {
		t.Fatal("device_id mismatch switched the pair")
	}
	// First authenticated send with the new pair: accepted, and the old pair is refused from then on.
	if c := e.sendIngest(newP, "net.connect"); c != 200 {
		t.Fatalf("new: %d", c)
	}
	if e.pending() {
		t.Fatal("pair still pending after the switch")
	}
	for name, p := range map[string]pair{"old": oldP, "old token + new cert": {oldP.token, newP.fp}, "new token + old cert": {newP.token, oldP.fp}} {
		if c := e.sendIngest(p, "net.dns"); c != 401 {
			t.Fatalf("%s after switch: %d", name, c)
		}
	}
	if c := e.sendIngest(newP, "net.dns"); c != 200 {
		t.Fatalf("new again: %d", c)
	}
	// History is not split: all events (3 + 1 + 1 accepted) belong to the same device_id.
	ids, _ := e.st.DeviceIDs(context.Background())
	if len(ids) != 1 || e.eventCount(e.dev.DeviceID) != 4 {
		t.Fatalf("devices %v, events %d", ids, e.eventCount(e.dev.DeviceID))
	}
}

func TestRenewalSwitchoverOnPing(t *testing.T) {
	e := newEnv(t, nil)
	oldP := pair{e.dev.DeviceToken, e.fp}
	newP := pairOf(t, e.renew())
	if c := e.sendPing(oldP); c != 200 || !e.pending() {
		t.Fatalf("old ping: %d pending=%v", c, e.pending())
	}
	if c := e.sendPing(newP); c != 200 || e.pending() {
		t.Fatalf("new ping: %d pending=%v", c, e.pending())
	}
	if c := e.sendPing(oldP); c != 401 {
		t.Fatalf("old ping after switch: %d", c)
	}
}

func TestDoubleRenewalBeforeSwitch(t *testing.T) {
	e := newEnv(t, nil)
	oldP := pair{e.dev.DeviceToken, e.fp}
	first := pairOf(t, e.renew())
	second := pairOf(t, e.renew())
	if c := e.sendIngest(first, "net.dns"); c != 401 {
		t.Fatalf("replaced pending pair: %d", c)
	}
	if c := e.sendIngest(oldP, "net.dns"); c != 200 {
		t.Fatalf("old pair after double renewal: %d", c)
	}
	// The replaced pair cannot be mixed with the new one either.
	if c := e.sendIngest(pair{second.token, first.fp}, "net.dns"); c != 401 {
		t.Fatalf("mix of two pending generations: %d", c)
	}
	if c := e.sendIngest(second, "net.dns"); c != 200 || e.pending() {
		t.Fatalf("second pair: %d", c)
	}
	if c := e.sendIngest(oldP, "net.dns"); c != 401 {
		t.Fatalf("old after switch: %d", c)
	}
}

func TestRevokeInvalidatesBothPairs(t *testing.T) {
	e := newEnv(t, nil)
	oldP := pair{e.dev.DeviceToken, e.fp}
	newP := pairOf(t, e.renew())
	if err := e.st.RevokeDevice(context.Background(), e.dev.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]pair{"old": oldP, "new": newP} {
		if c := e.sendIngest(p, "net.dns"); c != 401 {
			t.Fatalf("%s after revoke: %d", name, c)
		}
		if c := e.sendPing(p); c != 401 {
			t.Fatalf("%s ping after revoke: %d", name, c)
		}
	}
	// Revoked after the switch: the new pair is refused too.
	e2 := newEnv(t, nil)
	p2 := pairOf(t, e2.renew())
	if c := e2.sendPing(p2); c != 200 {
		t.Fatalf("switch: %d", c)
	}
	_ = e2.st.RevokeDevice(context.Background(), e2.dev.DeviceID, time.Now())
	if c := e2.sendPing(p2); c != 401 {
		t.Fatalf("revoked after switch: %d", c)
	}
}

func TestRenewalWithoutRequiredCert(t *testing.T) {
	// Without client-cert enforcement a missing fingerprint is allowed, but a wrong one never is,
	// and the pending token is still only accepted with the pending certificate.
	e := newEnv(t, map[string]string{"VIGIE_REQUIRE_CLIENT_CERT": "false"})
	oldP := pair{e.dev.DeviceToken, e.fp}
	newP := pairOf(t, e.renew())
	if c := e.sendPing(pair{newP.token, oldP.fp}); c != 401 {
		t.Fatalf("mix: %d", c)
	}
	if c := e.sendPing(pair{newP.token, ""}); c != 200 || e.pending() {
		t.Fatalf("no cert: %d", c)
	}
}

// Contract §3: 400 only for an unreadable or invalid batch envelope, never for a defect of one event.
func TestBadRequestOnlyForEnvelope(t *testing.T) {
	e := newEnv(t, nil)
	now := time.Now()
	good := e.event(now, "net.dns", 0, nil)
	goodJSON, _ := json.Marshal(good)
	goodID := good["id"].(string)
	const badID = "01JCQ8Z3K4M5N6P7Q8R9S0ABCD"
	deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	// Per-event defects: each lands in "rejected", the good event is still accepted, status 200.
	perEvent := map[string]string{
		"nesting beyond encoding/json":   fmt.Sprintf(`{"id":%q,"ts":%q,"seq":1,"boot_id":"b","elapsed_ms":1,"type":"x.y","sev":0,"data":{"a":%s}}`, badID, model_ts(now), deep),
		"nesting before id":              fmt.Sprintf(`{"data":{"a":%s},"id":%q}`, deep, badID),
		"event is a number":              `42`,
		"event is null":                  `null`,
		"event is a string":              `"x"`,
		"event is an array":              `[1,2]`,
		"empty object":                   `{}`,
		"bad type":                       fmt.Sprintf(`{"id":%q,"ts":%q,"seq":1,"boot_id":"b","elapsed_ms":1,"type":"NOPE","sev":0}`, badID, model_ts(now)),
		"bad ts":                         fmt.Sprintf(`{"id":%q,"ts":"x","seq":1,"boot_id":"b","elapsed_ms":1,"type":"x.y","sev":0}`, badID),
		"data not an object":             fmt.Sprintf(`{"id":%q,"ts":%q,"seq":1,"boot_id":"b","elapsed_ms":1,"type":"x.y","sev":0,"data":[1]}`, badID, model_ts(now)),
		"sev out of range":               fmt.Sprintf(`{"id":%q,"ts":%q,"seq":1,"boot_id":"b","elapsed_ms":1,"type":"x.y","sev":9}`, badID, model_ts(now)),
		"event over 256 KiB":             fmt.Sprintf(`{"id":%q,"ts":%q,"seq":1,"boot_id":"b","elapsed_ms":1,"type":"x.y","sev":0,"data":{"p":%q}}`, badID, model_ts(now), strings.Repeat("a", 300<<10)),
		"invalid UTF-8 and control":      fmt.Sprintf("{\"id\":%q,\"ts\":%q,\"seq\":1,\"boot_id\":\"b\\u0000\",\"elapsed_ms\":1,\"type\":\"x.y\",\"sev\":0,\"data\":{\"k\":\"\xff\"}}", badID, model_ts(now)),
		"escaped id with surrogate pair": fmt.Sprintf(`{"id":"😀","ts":%q}`, model_ts(now)),
	}
	for name, ev := range perEvent {
		t.Run(name, func(t *testing.T) {
			body := fmt.Sprintf(`{"device_id":%q,"agent_version":"1.0.0","events":[%s,%s]}`, e.dev.DeviceID, ev, goodJSON)
			rec := e.ingestRaw([]byte(body), true)
			if rec.Code != http.StatusOK {
				t.Fatalf("%d %.200s", rec.Code, rec.Body)
			}
			r := decodeJSON[ingestResp](t, rec)
			if r.Accepted+r.Duplicates+len(r.Rejected) != 2 {
				t.Fatalf("total: %+v", r)
			}
			if r.Accepted+r.Duplicates != 1 {
				t.Fatalf("good event lost: %+v", r)
			}
			if len(r.Rejected) != 1 {
				t.Fatalf("defective event not rejected: %+v", r)
			}
			// The id is returned when it can be read, so that the agent drops the right event.
			if strings.HasPrefix(name, "nesting") && r.Rejected[0].ID != badID {
				t.Fatalf("rejected id %q, want %q", r.Rejected[0].ID, badID)
			}
		})
	}
	_ = goodID
	// Envelope defects: 400.
	envelope := map[string]string{
		"not JSON":              `{`,
		"not an object":         `[]`,
		"trailing data":         fmt.Sprintf(`{"device_id":%q,"events":[]} x`, e.dev.DeviceID),
		"events missing":        fmt.Sprintf(`{"device_id":%q}`, e.dev.DeviceID),
		"events null":           fmt.Sprintf(`{"device_id":%q,"events":null}`, e.dev.DeviceID),
		"events not an array":   fmt.Sprintf(`{"device_id":%q,"events":{}}`, e.dev.DeviceID),
		"events unterminated":   fmt.Sprintf(`{"device_id":%q,"events":[{"a":1}`, e.dev.DeviceID),
		"device_id not string":  `{"device_id":5,"events":[]}`,
		"agent_version number":  fmt.Sprintf(`{"device_id":%q,"agent_version":1,"events":[]}`, e.dev.DeviceID),
		"syntax error in event": fmt.Sprintf(`{"device_id":%q,"events":[{"id":}]}`, e.dev.DeviceID),
	}
	for name, body := range envelope {
		t.Run("envelope/"+name, func(t *testing.T) {
			if rec := e.ingestRaw([]byte(body), true); rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d %s", rec.Code, rec.Body)
			}
		})
	}
	// Fields the server ignores, in any order, and an empty batch are fine.
	ok := fmt.Sprintf(`{"extra":{"x":[1,{"y":null}]},"events":[ %s , %s ],"device_id":%q,"sent_at":"2026-11-15T21:45:00.000Z"}`, goodJSON, goodJSON, e.dev.DeviceID)
	if r := decodeJSON[ingestResp](t, e.ingestRaw([]byte(ok), true)); r.Accepted+r.Duplicates != 2 {
		t.Fatalf("%+v", r)
	}
	if rec := e.ingestRaw([]byte(fmt.Sprintf(`{"device_id":%q,"events":[]}`, e.dev.DeviceID)), true); rec.Code != http.StatusOK {
		t.Fatalf("empty batch: %d", rec.Code)
	}
}

func model_ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
