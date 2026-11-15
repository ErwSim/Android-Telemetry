package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
)

func ingestRaw(t *testing.T, st *Store, evs []map[string]any) {
	t.Helper()
	now := time.Now()
	var parsed []*model.Event
	for i, m := range evs {
		m["id"] = fmt.Sprintf("01JCQ8Z3K4M5N6P7Q8R9S%05d", i)
		m["ts"] = model.FormatTS(now.Add(-time.Duration(i) * time.Minute))
		m["seq"], m["boot_id"], m["elapsed_ms"], m["sev"] = i, "b", 1, 0
		raw, _ := json.Marshal(m)
		e, err := model.ParseEvent(raw, now)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, e)
	}
	if _, _, err := st.Ingest(context.Background(), "dev_1", "", parsed, now); err != nil {
		t.Fatal(err)
	}
}

func snapshot(t *testing.T, st *Store) []string {
	t.Helper()
	rows, err := st.r.Query(`SELECT kind, hour_ms, device_id, package, key, count, bytes FROM top_counts`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k, d, p, key string
		var h, c, b int64
		if err := rows.Scan(&k, &h, &d, &p, &key, &c, &b); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprint(k, h, d, p, key, c, b))
	}
	sort.Strings(out)
	return out
}

// TestMigration2RebuildMatchesIngest checks that the SQL rebuild of top_counts
// (migration 2) gives the same aggregates as the Go code used at ingestion.
func TestMigration2RebuildMatchesIngest(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "vigie.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ingestRaw(t, st, []map[string]any{
		{"type": "net.dns", "data": map[string]any{"package": "com.google.android.gms", "hostname": "App-Measurement.com."}},
		{"type": "net.dns", "data": map[string]any{"hostname": "nopkg.example"}},
		{"type": "net.dns", "data": map[string]any{"package": "p", "hostname": 12}},
		{"type": "net.connect", "data": map[string]any{"package": "com.whatsapp", "ip": "157.240.1.1", "port": 443}},
		{"type": "net.connect", "data": map[string]any{"package": "com.whatsapp", "ip": "2a03:2880::1", "port": 5222}},
		{"type": "net.connect", "data": map[string]any{"ip": "1.1.1.1"}},
		{"type": "net.usage", "data": map[string]any{"apps": []any{map[string]any{"package": "a", "rx_bytes": 5, "tx_bytes": 7}, map[string]any{"package": "b", "rx_bytes": -3}, "x"}}},
		{"type": "app.foreground", "data": map[string]any{"package": "a", "event": "resumed"}},
		{"type": "app.foreground", "data": map[string]any{"package": "a", "event": "paused"}},
		{"type": "app.notification", "data": map[string]any{"package": "a", "event": "posted"}},
		{"type": "app.notification", "data": map[string]any{"package": "a", "event": "removed"}},
	})
	before := snapshot(t, st)
	if len(before) < 10 {
		t.Fatalf("too few aggregates: %v", before)
	}
	if _, err := st.w.Exec(migrations[1]); err != nil {
		t.Fatal(err)
	}
	after := snapshot(t, st)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("rebuild differs:\ningest  %v\nrebuild %v", before, after)
	}
}

func TestSchemaVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vigie.db")
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var v int
	_ = st.w.QueryRow("PRAGMA user_version").Scan(&v)
	st.Close()
	if v != SchemaVersion {
		t.Fatalf("user_version %d", v)
	}
	// Reopening is idempotent.
	st, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
}

func ingestAt(t *testing.T, st *Store, ts time.Time, typ string, data map[string]any) {
	t.Helper()
	ingestSeq++
	raw, _ := json.Marshal(map[string]any{"id": fmt.Sprintf("01JCQ8Z3K4M5N6P7Q8R9T%05d", ingestSeq), "ts": model.FormatTS(ts),
		"seq": ingestSeq, "boot_id": "b", "elapsed_ms": 1, "sev": 0, "type": typ, "data": data})
	e, err := model.ParseEvent(raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Ingest(context.Background(), "dev_1", "", []*model.Event{e}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

var ingestSeq int

func apps(names ...string) []any {
	var out []any
	for _, n := range names {
		out = append(out, map[string]any{"package": n})
	}
	return out
}

// LatestApps groups the parts of an inventory by inventory_id when present,
// even when the parts are far apart in time or interleaved with another
// inventory having the same number of parts; the heuristic remains for agents
// that do not send inventory_id.
func TestLatestAppsByInventoryID(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "vigie.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	base := time.Now().UTC().Add(-48 * time.Hour)

	// Older agent without inventory_id: heuristic grouping.
	ingestAt(t, st, base, "app.inventory", map[string]any{"part": 1, "parts": 2, "apps": apps("a", "b")})
	ingestAt(t, st, base.Add(time.Second), "app.inventory", map[string]any{"part": 2, "parts": 2, "apps": apps("c")})
	snap, err := st.LatestApps(ctx, "dev_1")
	if err != nil || len(snap.Apps) != 3 || !snap.Complete {
		t.Fatalf("heuristic: %+v %v", snap, err)
	}

	// Inventory X: part 1 sent, part 2 arrives 2 h later (after a retry).
	// Inventory Y (incomplete, same parts count) is interleaved in between.
	t0 := base.Add(24 * time.Hour)
	ingestAt(t, st, t0, "app.inventory", map[string]any{"inventory_id": "X", "part": 1, "parts": 2, "apps": apps("x1")})
	ingestAt(t, st, t0.Add(10*time.Minute), "app.inventory", map[string]any{"inventory_id": "Y", "part": 1, "parts": 2, "apps": apps("y1")})
	ingestAt(t, st, t0.Add(2*time.Hour), "app.inventory", map[string]any{"inventory_id": "X", "part": 2, "parts": 2, "apps": apps("x2")})
	snap, err = st.LatestApps(ctx, "dev_1")
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(snap.Apps)
	if got != "[map[package:x1] map[package:x2]]" || !snap.Complete || snap.PartsReceived != 2 {
		t.Fatalf("by inventory_id: %s %+v", got, snap)
	}

	// A newer inventory Z, still incomplete: reported as such, without mixing in X or Y.
	ingestAt(t, st, t0.Add(3*time.Hour), "app.inventory", map[string]any{"inventory_id": "Z", "part": 2, "parts": 2, "apps": apps("z2")})
	snap, err = st.LatestApps(ctx, "dev_1")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(snap.Apps); got != "[map[package:z2]]" || snap.Complete || snap.PartsReceived != 1 {
		t.Fatalf("incomplete Z: %s %+v", got, snap)
	}
}
