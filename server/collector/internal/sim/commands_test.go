package sim

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/command"
	"github.com/erwsim/android-telemetry/server/collector/internal/model"
)

const testCode = "correct horse battery staple"

func signedCmd(t *testing.T, key []byte, device, typ, params string, issued, expires time.Time) AgentCommand {
	t.Helper()
	id := model.NewULID(time.Now())
	p := fmt.Sprintf(`{"v":1,"id":%q,"device_id":%q,"type":%q,"params":%s,"issued_at":%q,"expires_at":%q}`,
		id, device, typ, params, model.FormatTS(issued), model.FormatTS(expires))
	c := AgentCommand{ID: id, Payload: p}
	if key != nil {
		c.Sig = command.Sign(key, p)
	}
	return c
}

func TestAgentChecks(t *testing.T) {
	dev := "dev_0123456789abcdef"
	a, err := NewCommandAgent(nil, AgentOptions{DeviceID: dev, Code: testCode}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Contract vector: the agent's key is K of §8, and the vector signature verifies.
	vector := AgentCommand{ID: "01JCQ8Z3K4M5N6P7Q8R9S0T1V2", Sig: "GWiiJjYxiBHlG1lba410Zxb0kDHsINh4nS9u/GE/OaE=",
		Payload: `{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef","type":"lock","params":{"message":"Téléphone perdu, appelez le 01 23 45 67 89"},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-23T10:00:00.000Z"}`}
	if !command.Verify(a.key, vector.Payload, vector.Sig) {
		t.Fatal("contract vector does not verify with the simulated agent's key")
	}
	now := time.Now()
	ok := func(c AgentCommand) AgentCommand { return c }
	good := signedCmd(t, a.key, dev, "lock", `{"message":"Perdu"}`, now, now.Add(time.Hour))
	cases := []struct {
		name string
		cmd  AgentCommand
		want string
	}{
		{"simple", signedCmd(t, nil, dev, "ring", `{"duration_s":10}`, now, now.Add(time.Hour)), ""},
		{"signed lock", ok(good), ""},
		{"id differs", AgentCommand{ID: model.NewULID(now), Payload: good.Payload, Sig: good.Sig}, "malformed"},
		{"not json", AgentCommand{ID: "x", Payload: "{"}, "malformed"},
		{"wrong device", signedCmd(t, nil, "dev_autre", "ring", `{}`, now, now.Add(time.Hour)), "wrong_device"},
		{"unknown type", signedCmd(t, nil, dev, "reboot", `{}`, now, now.Add(time.Hour)), "unknown_type"},
		{"bad signature", AgentCommand{ID: good.ID, Payload: good.Payload, Sig: command.Sign([]byte("autre clé"), good.Payload)}, "bad_signature"},
		{"unsigned lock", AgentCommand{ID: good.ID, Payload: good.Payload}, "bad_signature"},
		{"wipe not allowed", signedCmd(t, a.key, dev, "wipe", `{}`, now, now.Add(time.Hour)), "disabled"},
		{"expired", signedCmd(t, nil, dev, "ring", `{}`, now.Add(-time.Hour), now.Add(-6*time.Minute)), "expired"},
		{"within clock tolerance", signedCmd(t, nil, dev, "ring", `{}`, now.Add(-time.Hour), now.Add(-4*time.Minute)), ""},
		{"bad params", signedCmd(t, nil, dev, "ring", `{"duration_s":999}`, now, now.Add(time.Hour)), "bad_params"},
	}
	for _, c := range cases {
		if _, got := a.Check(c.cmd); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	a.seen = append(a.seen, good.ID)
	if _, got := a.Check(good); got != "replay" {
		t.Fatalf("replay: %q", got)
	}
	// 2 bad signatures above; 3 more, then any sensitive command is refused for an hour.
	for range 3 {
		a.Check(AgentCommand{ID: good.ID, Payload: good.Payload, Sig: "AAAA"})
	}
	if _, got := a.Check(signedCmd(t, a.key, dev, "lock", `{}`, now, now.Add(time.Hour))); got != "locked_out" {
		t.Fatalf("after 5 bad signatures: %q", got)
	}
	if _, got := a.Check(signedCmd(t, nil, dev, "ring", `{}`, now, now.Add(time.Hour))); got != "" {
		t.Fatalf("simple command during lock-out: %q", got)
	}
	noCode, _ := NewCommandAgent(nil, AgentOptions{DeviceID: dev}, nil)
	if _, got := noCode.Check(good); got != "no_code_configured" {
		t.Fatalf("no code: %q", got)
	}
	if _, err := NewCommandAgent(nil, AgentOptions{DeviceID: dev, Code: "court"}, nil); err == nil {
		t.Fatal("short code accepted")
	}
	skewed := &CommandAgent{opts: AgentOptions{DeviceID: dev, ClockSkew: 2 * time.Hour}, key: a.key}
	if _, got := skewed.Check(signedCmd(t, nil, dev, "ring", `{}`, now, now.Add(time.Hour))); got != "expired" {
		t.Fatalf("clock ahead: %q", got)
	}
}

func TestNotificationContentAndInject(t *testing.T) {
	start := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	var dns int
	g := New(Options{Start: start, Seed: 3, Rate: 3, SeqBase: 1, NotificationContent: true, OnDNS: func(time.Time, string) { dns++ }})
	evs := g.Advance(start.Add(12 * time.Hour))
	g.Inject(start.Add(12*time.Hour), "command.result", 0, map[string]any{"command_id": "x", "status": "executed"})
	g.Locate(start.Add(12 * time.Hour))
	evs = append(evs, g.Advance(start.Add(12*time.Hour+time.Second))...)
	evs = append(evs, g.Drain()...)
	var withContent, without, redacted, injected, netDNS int
	for _, e := range evs {
		switch e.Type {
		case "app.notification":
			if e.Data["event"] != "posted" {
				continue
			}
			if _, ok := e.Data["importance"]; !ok {
				t.Fatalf("no importance: %v", e.Data)
			}
			if title, ok := e.Data["title"].(string); ok {
				withContent++
				text := e.Data["text"].(string)
				if e.Data["redacted"] == true {
					redacted++
				}
				if len(text) > 512 || len(title) > 512 || strings.ContainsAny(text, "0123456789") && e.Data["redacted"] == true &&
					codeRe.MatchString(text) {
					t.Fatalf("unmasked code: %q", text)
				}
			} else {
				without++
			}
		case "command.result", "location.fix":
			if e.TS == model.FormatTS(start.Add(12*time.Hour)) {
				injected++
			}
		case "net.dns":
			n := 1
			if c, ok := e.Data["count"].(int); ok {
				n = c
			}
			netDNS += n
		}
	}
	if withContent == 0 || without == 0 || redacted == 0 || injected != 2 {
		t.Fatalf("content %d, without %d, redacted %d, injected %d", withContent, without, redacted, injected)
	}
	if dns != netDNS {
		t.Fatalf("fake AdGuard fed %d queries, net.dns totals %d", dns, netDNS)
	}
	raw, _ := json.Marshal(evs[len(evs)-1])
	if _, err := model.ParseEvent(raw, start.Add(13*time.Hour)); err != nil {
		t.Fatal(err)
	}
}
