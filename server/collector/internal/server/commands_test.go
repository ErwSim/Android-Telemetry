package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/command"
	"github.com/erwsim/android-telemetry/server/collector/internal/enroll"
	"github.com/erwsim/android-telemetry/server/collector/internal/model"
	"github.com/erwsim/android-telemetry/server/collector/internal/ratelimit"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

func cmdPayload(id, device, typ, params string, issued, expires time.Time) string {
	return fmt.Sprintf(`{"v":1,"id":%q,"device_id":%q,"type":%q,"params":%s,"issued_at":%q,"expires_at":%q}`,
		id, device, typ, params, model.FormatTS(issued), model.FormatTS(expires))
}

func (e *env) createCommand(c *http.Cookie, body map[string]any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	return e.do(http.MethodPost, "/api/console/commands", bytes.NewReader(b), withCookie(c),
		withHeader("X-Requested-With", "vigie"), withHeader("Content-Type", "application/json"))
}

func (e *env) simpleCommand(c *http.Cookie, typ, params string) (string, *httptest.ResponseRecorder) {
	id := model.NewULID(time.Now())
	now := time.Now()
	p := cmdPayload(id, e.dev.DeviceID, typ, params, now, now.Add(time.Hour))
	return id, e.createCommand(c, map[string]any{"device_id": e.dev.DeviceID, "payload": p})
}

func (e *env) agentReq(method, path string, body io.Reader, dev *enroll.File) *httptest.ResponseRecorder {
	if dev == nil {
		dev = e.dev
	}
	fp := e.fp
	if dev != e.dev {
		fp = pairOf(e.t, dev).fp
	}
	return e.do(method, path, body, withHeader("Authorization", "Bearer "+dev.DeviceToken), withHeader(CertHeader, fp),
		withHeader("Content-Type", "application/json"))
}

func (e *env) poll(dev *enroll.File) []agentCommand {
	e.t.Helper()
	rec := e.agentReq(http.MethodGet, "/api/v1/commands", nil, dev)
	if rec.Code != http.StatusOK {
		e.t.Fatalf("poll: %d %s", rec.Code, rec.Body)
	}
	var r struct {
		Commands []agentCommand `json:"commands"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		e.t.Fatal(err)
	}
	return r.Commands
}

func (e *env) result(id, status, detail string, dev *enroll.File) int {
	b, _ := json.Marshal(map[string]string{"status": status, "detail": detail, "at": model.FormatTS(time.Now())})
	return e.agentReq(http.MethodPost, "/api/v1/commands/"+id+"/result", bytes.NewReader(b), dev).Code
}

type listedCommand struct {
	ID, DeviceID, Type, Status, CreatedBy, Detail string
	Params                                        map[string]any
	Signed                                        bool
	DeliveredAt                                   *string `json:"delivered_at"`
	ResultAt                                      *string `json:"result_at"`
}

func (e *env) commands(c *http.Cookie) map[string]listedCommand {
	e.t.Helper()
	rec := e.get(c, "/api/console/commands", url.Values{"device_id": {e.dev.DeviceID}, "limit": {"500"}})
	if rec.Code != http.StatusOK {
		e.t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var r struct {
		Commands []struct {
			listedCommand
			DeviceID  string `json:"device_id"`
			CreatedBy string `json:"created_by"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		e.t.Fatal(err)
	}
	out := map[string]listedCommand{}
	for _, x := range r.Commands {
		lc := x.listedCommand
		lc.DeviceID, lc.CreatedBy = x.DeviceID, x.CreatedBy
		out[lc.ID] = lc
	}
	return out
}

func (e *env) serverEvents(c *http.Cookie, typ string) []map[string]any {
	e.t.Helper()
	now := time.Now()
	rec := e.get(c, "/api/console/events", url.Values{"type": {typ}, "from": {model.FormatTS(now.Add(-3 * time.Hour))},
		"to": {model.FormatTS(now.Add(3 * time.Hour))}, "limit": {"500"}})
	if rec.Code != http.StatusOK {
		e.t.Fatalf("events: %d %s", rec.Code, rec.Body)
	}
	var r struct {
		Events []map[string]any `json:"events"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	return r.Events
}

func TestCommandLifecycle(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	id, rec := e.simpleCommand(c, "ring", `{"duration_s":30}`)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), id) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if got := e.commands(c)[id]; got.Status != "pending" || got.Type != "ring" || got.Signed || got.CreatedBy != "admin" || got.Params["duration_s"] != float64(30) {
		t.Fatalf("listed %+v", got)
	}
	cmds := e.poll(nil)
	if len(cmds) != 1 || cmds[0].ID != id || cmds[0].Sig != "" || !strings.Contains(cmds[0].Payload, `"type":"ring"`) {
		t.Fatalf("poll %+v", cmds)
	}
	if again := e.poll(nil); len(again) != 0 {
		t.Fatalf("delivered command sent again at once: %+v", again)
	}
	if got := e.commands(c)[id]; got.Status != "delivered" || got.DeliveredAt == nil {
		t.Fatalf("after poll %+v", got)
	}
	cancel := e.do(http.MethodPost, "/api/console/commands/"+id+"/cancel", nil, withCookie(c), withHeader("X-Requested-With", "vigie"))
	if cancel.Code != http.StatusConflict {
		t.Fatalf("cancel of a delivered command: %d", cancel.Code)
	}
	if code := e.result(id, "executed", "", nil); code != http.StatusNoContent {
		t.Fatalf("result: %d", code)
	}
	// Duplicate and contradictory results are acknowledged without effect.
	if code := e.result(id, "refused", "replay", nil); code != http.StatusNoContent {
		t.Fatalf("duplicate result: %d", code)
	}
	if code := e.result(id, "failed", "boom", nil); code != http.StatusNoContent {
		t.Fatalf("second result: %d", code)
	}
	if got := e.commands(c)[id]; got.Status != "executed" || got.ResultAt == nil {
		t.Fatalf("after result %+v", got)
	}
	// Unknown command, invalid status, foreign device.
	if code := e.result(model.NewULID(time.Now()), "executed", "", nil); code != http.StatusNotFound {
		t.Fatalf("unknown command result: %d", code)
	}
	if code := e.result(id, "done", "", nil); code != http.StatusBadRequest {
		t.Fatalf("invalid status: %d", code)
	}
	other, err := enroll.Create(context.Background(), e.st, e.ca, enroll.Params{Name: "autre", IngestURL: "https://ingest.example.org"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := e.simpleCommand(c, "locate", `{}`)
	if code := e.result(id2, "executed", "", other); code != http.StatusNotFound {
		t.Fatalf("result from another device: %d", code)
	}
	if cmds := e.poll(other); len(cmds) != 0 {
		t.Fatalf("other device received %+v", cmds)
	}
	// Server events: issued (x2) and reported, with source "server".
	issued := e.serverEvents(c, "command.issued")
	reported := e.serverEvents(c, "command.reported")
	if len(issued) != 2 || len(reported) != 1 || issued[0]["source"] != "server" {
		t.Fatalf("server events: %v / %v", issued, reported)
	}
	if d := reported[0]["data"].(map[string]any); d["command_id"] != id || d["status"] != "executed" || d["type"] != "ring" {
		t.Fatalf("reported %v", d)
	}
}

func TestCommandValidation(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	now := time.Now()
	dev := e.dev.DeviceID
	mk := func(typ, params string, issued, expires time.Time) (string, string) {
		id := model.NewULID(time.Now())
		return id, cmdPayload(id, dev, typ, params, issued, expires)
	}
	sig := "GWiiJjYxiBHlG1lba410Zxb0kDHsINh4nS9u/GE/OaE="
	_, lock := mk("lock", `{"message":"Perdu"}`, now, now.Add(7*24*time.Hour))
	_, ring := mk("ring", `{}`, now, now.Add(time.Hour))
	_, wipe := mk("wipe", `{}`, now, now.Add(time.Hour))
	_, late := mk("ring", `{}`, now.Add(-2*time.Hour), now.Add(-time.Hour))
	_, old := mk("ring", `{}`, now.Add(-time.Hour), now.Add(time.Hour))
	_, long := mk("ring", `{}`, now, now.Add(31*24*time.Hour))
	_, bad := mk("ring", `{"duration_s":301}`, now, now.Add(time.Hour))
	_, unknown := mk("reboot", `{}`, now, now.Add(time.Hour))
	otherDev := strings.Replace(ring, dev, "dev_autre", 1)
	cases := []struct {
		name string
		body map[string]any
		code int
		err  string
	}{
		{"sensitive without sig", map[string]any{"device_id": dev, "payload": lock}, 400, "signature_required"},
		{"sensitive with bad sig", map[string]any{"device_id": dev, "payload": lock, "sig": "abc"}, 400, "invalid_signature"},
		{"wipe without sig", map[string]any{"device_id": dev, "payload": wipe}, 400, "signature_required"},
		{"simple with sig", map[string]any{"device_id": dev, "payload": ring, "sig": sig}, 400, "signature_not_allowed"},
		{"expired", map[string]any{"device_id": dev, "payload": late}, 400, "expired"},
		{"issued long ago", map[string]any{"device_id": dev, "payload": old}, 400, "invalid_validity"},
		{"validity > 30 days", map[string]any{"device_id": dev, "payload": long}, 400, "invalid_validity"},
		{"bad params", map[string]any{"device_id": dev, "payload": bad}, 400, "bad_params"},
		{"unknown type", map[string]any{"device_id": dev, "payload": unknown}, 400, "unknown_type"},
		{"device mismatch", map[string]any{"device_id": "dev_autre", "payload": ring}, 400, "wrong_device"},
		{"unknown device", map[string]any{"device_id": "dev_autre", "payload": otherDev}, 404, "not_found"},
		{"payload not string", map[string]any{"device_id": dev, "payload": map[string]any{"v": 1}}, 400, "invalid_json"},
		{"unknown field", map[string]any{"device_id": dev, "payload": ring, "status": "executed"}, 400, "invalid_json"},
		{"id mismatch", map[string]any{"device_id": dev, "payload": ring, "id": model.NewULID(now)}, 400, "invalid_payload"},
	}
	for _, tc := range cases {
		rec := e.createCommand(c, tc.body)
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), `"error":"`+tc.err+`"`) {
			t.Errorf("%s: %d %s", tc.name, rec.Code, rec.Body)
		}
	}
	// Valid sensitive command with a well-formed signature; the same id is refused afterwards.
	lockID, lock2 := mk("lock", `{"message":"Téléphone perdu"}`, now, now.Add(7*24*time.Hour))
	if rec := e.createCommand(c, map[string]any{"device_id": dev, "payload": lock2, "sig": sig, "id": lockID}); rec.Code != http.StatusCreated {
		t.Fatalf("signed lock: %d %s", rec.Code, rec.Body)
	}
	if rec := e.createCommand(c, map[string]any{"device_id": dev, "payload": lock2, "sig": sig}); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate id: %d %s", rec.Code, rec.Body)
	}
	got := e.poll(nil)
	if len(got) != 1 || got[0].Payload != lock2 || got[0].Sig != sig {
		t.Fatalf("relayed %+v", got)
	}
	// CSRF header and session.
	b, _ := json.Marshal(map[string]any{"device_id": dev, "payload": ring})
	if rec := e.do(http.MethodPost, "/api/console/commands", bytes.NewReader(b), withCookie(c)); rec.Code != http.StatusForbidden {
		t.Fatalf("without X-Requested-With: %d", rec.Code)
	}
	if rec := e.do(http.MethodPost, "/api/console/commands", bytes.NewReader(b), withHeader("X-Requested-With", "vigie")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("without session: %d", rec.Code)
	}
	// Revoked device.
	if err := e.st.RevokeDevice(context.Background(), dev, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, ring2 := mk("ring", `{}`, now, now.Add(time.Hour))
	if rec := e.createCommand(c, map[string]any{"device_id": dev, "payload": ring2}); rec.Code != http.StatusConflict {
		t.Fatalf("revoked device: %d %s", rec.Code, rec.Body)
	}
}

func TestCommandPayloadRelayedByteForByte(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	now := time.Now()
	id := model.NewULID(now)
	// Unusual but valid spacing, key order and escapes: the agent must receive exactly these bytes.
	p := fmt.Sprintf(`{ "type" : "lock", "v":1, "id":"%s",  "device_id":"%s", "params":{"message":"été <b>&amp;</b> \"x\"\nfin"},`+
		` "issued_at":"%s","expires_at":"%s" }`, id, e.dev.DeviceID, model.FormatTS(now), model.FormatTS(now.Add(time.Hour)))
	sig := strings.Repeat("A", 43) + "="
	if rec := e.createCommand(c, map[string]any{"device_id": e.dev.DeviceID, "payload": p, "sig": sig}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	got := e.poll(nil)
	if len(got) != 1 || got[0].Payload != p {
		t.Fatalf("payload altered:\n%q\n%q", p, got[0].Payload)
	}
	if lc := e.commands(c)[id]; lc.Params["message"] != "été <b>&amp;</b> \"x\"\nfin" {
		t.Fatalf("params %v", lc.Params)
	}
}

func TestCommandLimitsAndCancel(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	var ids []string
	for i := range cmdMaxPending {
		id, rec := e.simpleCommand(c, "vibrate", `{"duration_s":5}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("command %d: %d %s", i, rec.Code, rec.Body)
		}
		ids = append(ids, id)
	}
	if _, rec := e.simpleCommand(c, "vibrate", `{}`); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("11th pending: %d %s", rec.Code, rec.Body)
	}
	cancel := func(id string) int {
		return e.do(http.MethodPost, "/api/console/commands/"+id+"/cancel", nil, withCookie(c), withHeader("X-Requested-With", "vigie")).Code
	}
	if code := e.do(http.MethodPost, "/api/console/commands/"+ids[0]+"/cancel", nil, withCookie(c)).Code; code != http.StatusForbidden {
		t.Fatalf("cancel without CSRF header: %d", code)
	}
	for _, id := range ids {
		if code := cancel(id); code != http.StatusNoContent {
			t.Fatalf("cancel: %d", code)
		}
	}
	if code := cancel(ids[0]); code != http.StatusConflict {
		t.Fatalf("second cancel: %d", code)
	}
	if code := cancel(model.NewULID(time.Now())); code != http.StatusNotFound {
		t.Fatalf("cancel unknown: %d", code)
	}
	if got := e.poll(nil); len(got) != 0 {
		t.Fatalf("cancelled commands delivered: %+v", got)
	}
	if n := len(e.serverEvents(c, "command.cancelled")); n != cmdMaxPending {
		t.Fatalf("cancelled events: %d", n)
	}
	// Hourly limit: 10 created so far.
	for i := range cmdPerHour - cmdMaxPending {
		if _, rec := e.simpleCommand(c, "stop_ring", `{}`); rec.Code != http.StatusCreated {
			t.Fatalf("command %d: %d %s", i, rec.Code, rec.Body)
		}
		e.poll(nil) // keep the pending count low
	}
	if _, rec := e.simpleCommand(c, "stop_ring", `{}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("21st in the hour: %d %s", rec.Code, rec.Body)
	}
}

// Cancellations racing with deliveries: a command is either delivered (and its cancellation refused)
// or cancelled (and never delivered).
func TestCommandCancelRace(t *testing.T) {
	e := newEnv(t, nil)
	e.srv.ingestDevice = ratelimit.New(1000, 1000, 100)
	c := e.session()
	for round := range cmdPerHour / cmdMaxPending {
		var ids []string
		for range cmdMaxPending {
			id, rec := e.simpleCommand(c, "ring", `{}`)
			if rec.Code != http.StatusCreated {
				t.Fatalf("round %d: %d %s", round, rec.Code, rec.Body)
			}
			ids = append(ids, id)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		delivered := map[string]bool{}
		cancelled := map[string]bool{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				for _, cmd := range e.poll(nil) {
					mu.Lock()
					delivered[cmd.ID] = true
					mu.Unlock()
				}
			}
		}()
		for _, id := range ids {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				code := e.do(http.MethodPost, "/api/console/commands/"+id+"/cancel", nil, withCookie(c), withHeader("X-Requested-With", "vigie")).Code
				mu.Lock()
				defer mu.Unlock()
				switch code {
				case http.StatusNoContent:
					cancelled[id] = true
				case http.StatusConflict:
				default:
					t.Errorf("cancel: %d", code)
				}
			}(id)
		}
		wg.Wait()
		for _, cmd := range e.poll(nil) {
			delivered[cmd.ID] = true
		}
		listed := e.commands(c)
		for _, id := range ids {
			if delivered[id] == cancelled[id] {
				t.Fatalf("command %s delivered=%v cancelled=%v", id, delivered[id], cancelled[id])
			}
			want := "delivered"
			if cancelled[id] {
				want = "cancelled"
			}
			if listed[id].Status != want {
				t.Fatalf("command %s status %s, want %s", id, listed[id].Status, want)
			}
		}
		for id := range delivered {
			e.result(id, "executed", "", nil)
		}
	}
}

func TestCommandExpiry(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	id, rec := e.simpleCommand(c, "ring", `{}`)
	if rec.Code != http.StatusCreated {
		t.Fatal(rec.Code)
	}
	e.srv.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if got := e.commands(c)[id]; got.Status != "expired" {
		t.Fatalf("status past expiry: %s", got.Status)
	}
	if got := e.poll(nil); len(got) != 0 {
		t.Fatalf("expired command delivered: %+v", got)
	}
	e.srv.expireCommands(context.Background())
	if got := e.commands(c)[id]; got.Status != "expired" {
		t.Fatalf("stored status: %s", got.Status)
	}
	e.srv.now = time.Now
	if n := len(e.serverEvents(c, "command.expired")); n != 1 {
		t.Fatalf("expired events: %d", n)
	}
	// A late result of the agent is still recorded (it is the truth about the phone).
	if code := e.result(id, "executed", "", nil); code != http.StatusNoContent || e.commands(c)[id].Status != "executed" {
		t.Fatalf("late result: %d %s", code, e.commands(c)[id].Status)
	}
}

type sseMsg struct{ event, data string }

func readSSE(t *testing.T, sc *bufio.Scanner, ch chan<- sseMsg) {
	var m sseMsg
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if m.data != "" {
				ch <- m
			}
			m = sseMsg{}
		case strings.HasPrefix(line, "event: "):
			m.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			m.data = strings.TrimPrefix(line, "data: ")
		}
	}
	close(ch)
}

func (e *env) openStream(ts *httptest.Server) (*http.Response, chan sseMsg) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/commands/stream", nil)
	req.Header.Set("Authorization", "Bearer "+e.dev.DeviceToken)
	req.Header.Set(CertHeader, e.fp)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		e.t.Fatalf("stream: %d", resp.StatusCode)
	}
	ch := make(chan sseMsg, 16)
	go readSSE(e.t, bufio.NewScanner(resp.Body), ch)
	return resp, ch
}

func next(t *testing.T, ch <-chan sseMsg) (sseMsg, bool) {
	t.Helper()
	select {
	case m, ok := <-ch:
		return m, ok
	case <-time.After(5 * time.Second):
		t.Fatal("no message on the command stream")
	}
	return sseMsg{}, false
}

func TestCommandStream(t *testing.T) {
	var logs bytes.Buffer
	var logMu sync.Mutex
	e := newEnv(t, map[string]string{"VIGIE_CMD_KEEPALIVE_S": "5"})
	e.srv.log = slog.New(slog.NewTextHandler(&lockedWriter{w: &logs, mu: &logMu}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := e.session()
	ts := httptest.NewServer(e.h)
	defer ts.Close()
	defer e.srv.CloseStreams()

	// A command created before the connection is sent at once.
	id1, _ := e.simpleCommand(c, "ring", `{}`)
	resp1, ch1 := e.openStream(ts)
	defer resp1.Body.Close()
	m, _ := next(t, ch1)
	var got agentCommand
	if m.event != "command" || json.Unmarshal([]byte(m.data), &got) != nil || got.ID != id1 {
		t.Fatalf("first message %+v", m)
	}
	// A new command is pushed.
	now := time.Now()
	id2 := model.NewULID(now)
	secret := "Rendez-le au 01 23 45 67 89"
	p := cmdPayload(id2, e.dev.DeviceID, "lock", fmt.Sprintf(`{"message":%q}`, secret), now, now.Add(time.Hour))
	if rec := e.createCommand(c, map[string]any{"device_id": e.dev.DeviceID, "payload": p, "sig": strings.Repeat("A", 43) + "="}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	m, _ = next(t, ch1)
	if json.Unmarshal([]byte(m.data), &got) != nil || got.ID != id2 || got.Payload != p {
		t.Fatalf("pushed %+v", m)
	}
	rec := e.get(c, "/api/console/devices", nil)
	if !strings.Contains(rec.Body.String(), `"command_channel":{"connected":true,"mode":"stream","last_contact":"`) {
		t.Fatalf("devices: %s", rec.Body)
	}
	// A second connection of the same device replaces the first one.
	resp2, ch2 := e.openStream(ts)
	defer resp2.Body.Close()
	for {
		if _, ok := next(t, ch1); !ok {
			break
		}
	}
	id3, _ := e.simpleCommand(c, "locate", `{}`)
	m, _ = next(t, ch2)
	if json.Unmarshal([]byte(m.data), &got) != nil || got.ID != id3 {
		t.Fatalf("on the new stream %+v", m)
	}
	if code := e.result(id3, "executed", "", nil); code != http.StatusNoContent {
		t.Fatal(code)
	}
	resp2.Body.Close()
	deadline := time.Now().Add(5 * time.Second)
	for e.srv.cmdHub.connected(e.dev.DeviceID) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if e.srv.cmdHub.connected(e.dev.DeviceID) {
		t.Fatal("closed stream still registered")
	}
	rec = e.get(c, "/api/console/devices", nil)
	if !strings.Contains(rec.Body.String(), `"command_channel":{"connected":false,"mode":"stream"`) {
		t.Fatalf("devices after close: %s", rec.Body)
	}
	logMu.Lock()
	logText := logs.String()
	logMu.Unlock()
	if !strings.Contains(logText, "commande émise") || strings.Contains(logText, secret) || strings.Contains(logText, e.dev.DeviceToken) {
		t.Fatal("lock message or token in the process logs")
	}
	// Nor in the exported command.issued event.
	for _, ev := range e.serverEvents(c, "command.issued") {
		if b, _ := json.Marshal(ev); strings.Contains(string(b), secret) {
			t.Fatalf("lock message in the server event: %s", b)
		}
	}
}

func TestCommandStreamRevocationAndShutdown(t *testing.T) {
	e := newEnv(t, map[string]string{"VIGIE_CMD_KEEPALIVE_S": "5"})
	ts := httptest.NewServer(e.h)
	defer ts.Close()
	resp, ch := e.openStream(ts)
	defer resp.Body.Close()
	if err := e.st.RevokeDevice(context.Background(), e.dev.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Closed at the next keep-alive (5 s).
	deadline := time.After(10 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				goto revoked
			}
		case <-deadline:
			t.Fatal("stream of a revoked device still open")
		}
	}
revoked:
	e2 := newEnv(t, nil)
	ts2 := httptest.NewServer(e2.h)
	defer ts2.Close()
	resp2, ch2 := e2.openStream(ts2)
	defer resp2.Body.Close()
	e2.srv.CloseStreams()
	for {
		if _, ok := next(t, ch2); !ok {
			break
		}
	}
	if code := e2.agentReq(http.MethodGet, "/api/v1/commands/stream", nil, nil).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("stream after shutdown: %d", code)
	}
}

func TestCommandHubBounded(t *testing.T) {
	h := newCmdHub(2)
	a, err1 := h.attach("a")
	_, err2 := h.attach("b")
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if _, err := h.attach("c"); err == nil {
		t.Fatal("third device accepted")
	}
	a2, err := h.attach("a") // replacing does not count twice
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.done:
	default:
		t.Fatal("replaced connection not stopped")
	}
	h.detach(a) // the old one leaving does not remove the new one
	if !h.connected("a") {
		t.Fatal("new connection removed by the old one")
	}
	h.detach(a2)
	if h.connected("a") {
		t.Fatal("still connected")
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// The contract test vector also passes the collector's checks end to end (as payload + sig).
func TestCommandContractVectorAccepted(t *testing.T) {
	p, err := command.Parse(`{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef","type":"lock","params":{"message":"Téléphone perdu, appelez le 01 23 45 67 89"},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-23T10:00:00.000Z"}`)
	if err != nil || !command.Sensitive(p.Type) || !command.ValidSignatureFormat("GWiiJjYxiBHlG1lba410Zxb0kDHsINh4nS9u/GE/OaE=") {
		t.Fatal(err)
	}
	_ = store.CmdPending
}

// The signature of a sensitive command is kept only while the command can still be handed to the agent:
// a copy of the database (or a backup) taken later holds no (payload, signature) pair of past commands
// to search the owner's command code offline. The console still shows the command as signed.
func TestCommandSignatureErasedOnceFinal(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	key, err := command.DeriveKey("correct horse battery staple", e.dev.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	signed := func(typ string, validity time.Duration) (string, string) {
		id := model.NewULID(time.Now())
		now := time.Now()
		p := cmdPayload(id, e.dev.DeviceID, typ, `{}`, now, now.Add(validity))
		sig := command.Sign(key, p)
		if rec := e.createCommand(c, map[string]any{"device_id": e.dev.DeviceID, "payload": p, "sig": sig}); rec.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rec.Code, rec.Body)
		}
		return id, sig
	}
	stored := func(id string) string {
		cmd, err := e.st.GetCommand(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		return cmd.Sig
	}

	// Result received: kept while pending and delivered (also after a non-final "replay"), erased afterwards.
	done, sig := signed("lock", time.Hour)
	if stored(done) != sig {
		t.Fatal("signature not stored while pending")
	}
	if cmds := e.poll(nil); len(cmds) != 1 || cmds[0].Sig != sig {
		t.Fatalf("poll %+v", cmds)
	}
	e.result(done, "refused", "replay", nil)
	if stored(done) != sig {
		t.Fatal("signature erased by a non-final result: the command could not be delivered again")
	}
	if code := e.result(done, "executed", "ok", nil); code != http.StatusNoContent {
		t.Fatal(code)
	}
	if got := stored(done); got != store.SigErased {
		t.Fatalf("signature kept after the result: %q", got)
	}

	// Cancelled.
	cancelled, _ := signed("clear_lock_message", time.Hour)
	if rec := e.do(http.MethodPost, "/api/console/commands/"+cancelled+"/cancel", nil, withCookie(c), withHeader("X-Requested-With", "vigie")); rec.Code != http.StatusNoContent {
		t.Fatalf("cancel: %d", rec.Code)
	}
	if got := stored(cancelled); got != store.SigErased {
		t.Fatalf("signature kept after cancellation: %q", got)
	}

	// Expired.
	expired, _ := signed("wipe", time.Minute)
	e.srv.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	e.srv.expireCommands(context.Background())
	e.srv.now = time.Now
	if got := stored(expired); got != store.SigErased {
		t.Fatalf("signature kept after expiry: %q", got)
	}

	// A simple command has no signature before or after; the console still sees which ones were signed.
	simple, _ := e.simpleCommand(c, "ring", `{}`)
	e.poll(nil)
	e.result(simple, "executed", "", nil)
	if got := stored(simple); got != "" {
		t.Fatalf("simple command: %q", got)
	}
	list := e.commands(c)
	if !list[done].Signed || !list[cancelled].Signed || !list[expired].Signed || list[simple].Signed {
		t.Fatalf("signed flags: %+v", list)
	}
	for _, typ := range []string{"command.reported", "command.cancelled", "command.expired"} {
		for _, ev := range e.serverEvents(c, typ) {
			if d := ev["data"].(map[string]any); d["command_id"] != simple && d["signed"] != true {
				t.Fatalf("%s lost the signed flag: %v", typ, d)
			}
		}
	}
	// Nothing left to deliver, and no marker ever reaches the agent.
	if cmds := e.poll(nil); len(cmds) != 0 {
		t.Fatalf("poll after final states: %+v", cmds)
	}
}
