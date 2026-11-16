package export

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
	"github.com/erwsim/android-telemetry/server/collector/internal/sim"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

func stored(typ string, sev int, data string) store.StoredEvent {
	return store.StoredEvent{PK: 1, ID: "01JCQ8Z3K4M5N6P7Q8R9S0T1V2", DeviceID: "dev_1", TSms: 1763243000000, ReceivedMS: 1763243001000,
		Seq: 7, BootID: "b", Type: typ, Sev: sev, Data: json.RawMessage(data)}
}

type lineT struct {
	Vigie struct {
		DeviceID   string         `json:"device_id"`
		DeviceName string         `json:"device_name"`
		ID         string         `json:"id"`
		TS         string         `json:"ts"`
		ReceivedAt string         `json:"received_at"`
		Seq        int64          `json:"seq"`
		Type       string         `json:"type"`
		Domain     string         `json:"domain"`
		Sev        int            `json:"sev"`
		Data       map[string]any `json:"data"`
	} `json:"vigie"`
}

func parse(t *testing.T, b []byte) lineT {
	t.Helper()
	if !bytes.HasPrefix(b, []byte(`{"vigie":{"device_id"`)) || !bytes.HasSuffix(b, []byte("\n")) || bytes.Count(b, []byte("\n")) != 1 {
		t.Fatalf("malformed line %q", b)
	}
	if len(b) > MaxLineBytes {
		t.Fatalf("line of %d bytes", len(b))
	}
	var l lineT
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLineBasic(t *testing.T) {
	lines := Lines(stored("net.dns", 0, `{"package":"com.google.android.gms","hostname":"app-measurement.com","addresses":["1.2.3.4"],"x":{"y":[1,2]}}`), "s25")
	if len(lines) != 1 {
		t.Fatalf("%d lines", len(lines))
	}
	l := parse(t, lines[0])
	v := l.Vigie
	if v.DeviceName != "s25" || v.Domain != "net" || v.Type != "net.dns" || v.TS != "2025-11-15T21:43:20.000Z" || v.Seq != 7 {
		t.Fatalf("bad line %+v", v)
	}
	if v.Data["hostname"] != "app-measurement.com" || len(v.Data["addresses"].([]any)) != 1 {
		t.Fatal("scalar arrays must be kept")
	}
}

func TestLineArraysOfObjects(t *testing.T) {
	data := `{"part":1,"parts":2,"apps":[{"package":"a","granted_dangerous":["p1"],"nested":[{"z":1}]},{"package":"b"},"weird"],
		"meta":{"list":[{"k":1}],"ok":[1,"a"]},"mixed":[1,{"a":1}]}`
	lines := Lines(stored("app.inventory", 0, data), "s25")
	if len(lines) != 3 { // main + 2 objects (the string element is skipped)
		t.Fatalf("%d lines", len(lines))
	}
	m := parse(t, lines[0]).Vigie
	if _, ok := m.Data["apps"]; ok {
		t.Fatal("array of objects kept")
	}
	if m.Data["apps_count"] != float64(3) || m.Data["mixed_count"] != float64(2) {
		t.Fatalf("counts %v", m.Data)
	}
	meta := m.Data["meta"].(map[string]any)
	if meta["list_count"] != float64(1) || meta["ok"] == nil {
		t.Fatalf("nested sanitizing %v", meta)
	}
	d0 := parse(t, lines[1]).Vigie
	if d0.Type != "app.inventory.app" || d0.ID != "01JCQ8Z3K4M5N6P7Q8R9S0T1V2#0" || d0.Domain != "app" || d0.Data["package"] != "a" {
		t.Fatalf("derived %+v", d0)
	}
	if d0.Data["nested_count"] != float64(1) || d0.Data["granted_dangerous"] == nil {
		t.Fatalf("derived element not sanitized %v", d0.Data)
	}
	if parse(t, lines[2]).Vigie.ID != "01JCQ8Z3K4M5N6P7Q8R9S0T1V2#1" {
		t.Fatal("derived index")
	}
}

func TestLineUsageAndWifiScan(t *testing.T) {
	lines := Lines(stored("net.usage", 0, `{"from":"2026-11-15T20:00:00Z","to":"2026-11-15T21:00:00Z","apps":[{"package":"p","rx_bytes":10,"tx_bytes":2,"transport":"wifi"}]}`), "")
	if len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	d := parse(t, lines[1]).Vigie
	if d.Type != "net.usage.app" || d.Data["from"] != "2026-11-15T20:00:00Z" || d.Data["to"] != "2026-11-15T21:00:00Z" || d.Data["rx_bytes"] != float64(10) {
		t.Fatalf("usage derived %+v", d)
	}
	lines = Lines(stored("net.wifi_scan", 0, `{"aps":[{"ssid":"a"},{"ssid":"b"}]}`), "")
	if len(lines) != 3 || parse(t, lines[2]).Vigie.Type != "net.wifi_scan.ap" || parse(t, lines[0]).Vigie.Data["aps_count"] != float64(2) {
		t.Fatal("wifi scan")
	}
}

func TestLineLocation(t *testing.T) {
	l := parse(t, Lines(stored("location.fix", 0, `{"lat":48.85,"lon":2.35,"acc_m":5}`), "")[0]).Vigie
	loc, ok := l.Data["location"].(map[string]any)
	if !ok || loc["lat"] != 48.85 || loc["lon"] != 2.35 {
		t.Fatalf("location %v", l.Data)
	}
	l = parse(t, Lines(stored("location.fix", 0, `{"lat":"x"}`), "")[0]).Vigie
	if _, ok := l.Data["location"]; ok {
		t.Fatal("location without coordinates")
	}
}

// Regression: a device-supplied data.location (any type, or a location.fix
// without valid coordinates) was exported as is, although the indexer maps
// vigie.data.location as geo_point and rejects the whole document otherwise.
func TestLineLocationReserved(t *testing.T) {
	for _, c := range []struct{ typ, data string }{
		{"net.dns", `{"hostname":"x","location":"ailleurs"}`},
		{"location.fix", `{"lat":"x","location":{"lat":"nord"}}`},
		{"net.wifi_scan", `{"aps":[{"ssid":"a","location":[1,2,3]}]}`},
	} {
		for i, line := range Lines(stored(c.typ, 0, c.data), "") {
			if v, ok := parse(t, line).Vigie.Data["location"]; ok {
				t.Errorf("%s line %d: device-supplied location exported: %v", c.typ, i, v)
			}
		}
	}
	l := parse(t, Lines(stored("location.fix", 0, `{"lat":1.5,"lon":2.5,"location":"x"}`), "")[0]).Vigie
	if loc, ok := l.Data["location"].(map[string]any); !ok || loc["lat"] != 1.5 || loc["lon"] != 2.5 {
		t.Fatalf("collector location replaced: %v", l.Data["location"])
	}
}

func TestLineTruncated(t *testing.T) {
	big := fmt.Sprintf(`{"text":%q}`, strings.Repeat("é", 20000))
	lines := Lines(stored("app.notification", 1, big), "s25")
	l := parse(t, lines[0]).Vigie
	if len(l.Data) != 1 || l.Data["truncated"] != true || l.Sev != 1 {
		t.Fatalf("not truncated: %v", l.Data)
	}
	// Just below the limit is kept.
	small := fmt.Sprintf(`{"text":%q}`, strings.Repeat("a", 30000))
	if parse(t, Lines(stored("x.y", 0, small), "")[0]).Vigie.Data["truncated"] != nil {
		t.Fatal("small line truncated")
	}
	// Derived lines are bounded too.
	el := fmt.Sprintf(`{"apps":[{"package":"p","label":%q}]}`, strings.Repeat("b", 40000))
	ls := Lines(stored("app.inventory", 0, el), "")
	if parse(t, ls[1]).Vigie.Data["truncated"] != true {
		t.Fatal("derived not truncated")
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func TestFileWriterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.ndjson")
	w := NewFileWriter(path, 1000, 2)
	line := []byte(`{"vigie":{"n":"` + strings.Repeat("x", 280) + `"}}` + "\n") // ~300 bytes
	for range 10 {
		if err := w.WriteLines([][]byte{line}); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	total := 0
	for _, p := range []string{path, path + ".1", path + ".2"} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s missing: %v", p, err)
		}
		if st.Size() > 1000 {
			t.Fatalf("%s is %d bytes", p, st.Size())
		}
		total += len(readLines(t, p))
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Fatal("more files than keep")
	}
	if total < 6 {
		t.Fatalf("only %d lines kept", total)
	}
}

func TestFileWriterTerminatesPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.ndjson")
	if err := os.WriteFile(path, []byte("{\"vigie\":{\"partial\""), 0o640); err != nil {
		t.Fatal(err)
	}
	w := NewFileWriter(path, 1<<20, 2)
	if err := w.WriteLines([][]byte{[]byte("{\"vigie\":{}}\n")}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	lines := readLines(t, path)
	if len(lines) != 2 || lines[1] != `{"vigie":{}}` {
		t.Fatalf("lines %q", lines)
	}
}

func TestFileWriterReopensMovedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.ndjson")
	w := NewFileWriter(path, 1<<20, 2)
	_ = w.WriteLines([][]byte{[]byte("{\"a\":1}\n")})
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	_ = w.WriteLines([][]byte{[]byte("{\"a\":2}\n")})
	w.Close()
	if l := readLines(t, path); len(l) != 1 || l[0] != `{"a":2}` {
		t.Fatalf("not reopened: %q", l)
	}
}

// TestExporterResume checks that events stored while the exporter was not
// running are exported after a restart, exactly once each when no crash occurs.
func TestExporterResume(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "vigie.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateDevice(ctx, &store.Device{DeviceID: "dev_1", Name: "s25", TokenHash: []byte("h"), CertSHA256: "x", CertPEM: "x", EnrolledAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	mk := func(n int) []*model.Event {
		var out []*model.Event
		for i := range n {
			ts := time.Now().Add(-time.Duration(n-i) * time.Second)
			raw, _ := json.Marshal(map[string]any{"id": sim.NewULID(ts, rng), "ts": model.FormatTS(ts), "seq": i, "boot_id": "b",
				"elapsed_ms": 1, "type": "net.wifi_scan", "sev": 0, "data": map[string]any{"aps": []any{map[string]any{"ssid": "a"}}}})
			e, err := model.ParseEvent(raw, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, e)
		}
		return out
	}
	// Events before the first start are not replayed.
	if _, err := st.Ingest(ctx, "dev_1", "", mk(3), time.Now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "out", "events.ndjson")
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	run := func() {
		e := New(st, path, 1<<20, 3, log)
		if err := e.Init(ctx); err != nil {
			t.Fatal(err)
		}
		c, cancel := context.WithCancel(ctx)
		go e.Run(c)
		e.Notify()
		deadline := time.Now().Add(5 * time.Second)
		for {
			max, _ := st.MaxEventPK(ctx)
			if e.Cursor() == max || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		e.Wait()
	}
	run()
	if _, err := os.Stat(path); err == nil && len(readLines(t, path)) != 0 {
		t.Fatal("history replayed on first start")
	}
	if _, err := st.Ingest(ctx, "dev_1", "", mk(5), time.Now()); err != nil {
		t.Fatal(err)
	}
	run()
	// Stored while the exporter is down, exported after restart.
	if _, err := st.Ingest(ctx, "dev_1", "", mk(4), time.Now()); err != nil {
		t.Fatal(err)
	}
	run()
	lines := readLines(t, path)
	if len(lines) != (5+4)*2 { // each wifi scan has one derived line
		t.Fatalf("%d lines", len(lines))
	}
	seen := map[string]bool{}
	for _, l := range lines {
		var x lineT
		if err := json.Unmarshal([]byte(l), &x); err != nil {
			t.Fatal(err)
		}
		if seen[x.Vigie.ID] {
			t.Fatalf("duplicate %s", x.Vigie.ID)
		}
		seen[x.Vigie.ID] = true
		if x.Vigie.DeviceName != "s25" {
			t.Fatal("device name")
		}
	}
}

// The export file exists as soon as the exporter is initialised, before any event (Wazuh
// would otherwise open it at its end when it appears and miss the first lines).
func TestExporterInitCreatesFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "vigie.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	path := filepath.Join(dir, "events.ndjson")
	e := New(st, path, 1<<20, 3, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := e.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer e.w.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("export file not created at start-up: %v", err)
	}
	if fi.Size() != 0 || fi.Mode().Perm() != 0o640 {
		t.Fatalf("size %d, mode %v", fi.Size(), fi.Mode().Perm())
	}
	// A missing directory is not fatal at start-up.
	e2 := New(st, filepath.Join(dir, "absent", "events.ndjson"), 1<<20, 3, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := e2.Init(ctx); err != nil {
		t.Fatalf("Init failed on a missing directory: %v", err)
	}
}

func TestLineSourceAndNotification(t *testing.T) {
	ev := stored("command.issued", 1, `{"command_id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","type":"lock","signed":true,"params":{}}`)
	ev.Source = "server"
	line := string(Lines(ev, "s25")[0])
	if !strings.Contains(line, `"source":"server"`) || !strings.HasPrefix(line, `{"vigie":{`) {
		t.Fatalf("server event line %s", line)
	}
	dev := string(Lines(stored("command.result", 0, `{"command_id":"x","status":"executed"}`), "s25")[0])
	if strings.Contains(dev, `"source"`) {
		t.Fatalf("device event carries a source: %s", dev)
	}
	// app.notification with content (contract §10): scalar fields exported as they are.
	n := string(Lines(stored("app.notification", 0, `{"package":"com.whatsapp","event":"posted","category":"msg","channel":"messages","ongoing":false,"importance":4,"title":"Alice","text":"Ton code : ••••••","redacted":true}`), "s25")[0])
	for _, want := range []string{`"title":"Alice"`, `"text":"Ton code : ••••••"`, `"redacted":true`, `"importance":4`, `"type":"app.notification"`, `"domain":"app"`} {
		if !strings.Contains(n, want) {
			t.Fatalf("notification line lacks %s: %s", want, n)
		}
	}
}
