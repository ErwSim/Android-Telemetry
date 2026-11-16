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
	if _, err := st.Ingest(context.Background(), "dev_1", "", parsed, now); err != nil {
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
// (migrations 2 and 3) gives the same aggregates as the Go code used at ingestion.
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
		// data.count: valid, bounds, and every value that must count 1.
		{"type": "net.dns", "data": map[string]any{"package": "w", "hostname": "weighted.example", "count": 5}},
		{"type": "net.dns", "data": map[string]any{"package": "w", "hostname": "weighted.example", "count": 1000000}},
		{"type": "net.dns", "data": map[string]any{"package": "w", "hostname": "weighted.example", "count": 1000001}},
		{"type": "net.dns", "data": map[string]any{"package": "w", "hostname": "weighted.example", "count": 0}},
		{"type": "net.dns", "data": map[string]any{"package": "w", "hostname": "weighted.example", "count": -3}},
		{"type": "net.dns", "data": map[string]any{"package": "w", "hostname": "weighted.example", "count": 3.5}},
		{"type": "net.dns", "data": map[string]any{"package": "w", "hostname": "weighted.example", "count": 3.0}},
		{"type": "net.dns", "data": map[string]any{"package": "w", "hostname": "weighted.example", "count": "7"}},
		{"type": "net.dns", "data": map[string]any{"package": "w", "hostname": "weighted.example", "count": json.Number("99999999999999999999")}},
		{"type": "net.connect", "data": map[string]any{"package": "w", "ip": "9.9.9.9", "port": 53, "count": 12, "last_event_ts": "2026-11-15T10:00:00.000Z"}},
		{"type": "net.connect", "data": map[string]any{"package": "w", "ip": "2001:db8::1", "port": 443, "count": 40}},
		// Not weighted: foreground and notifications stay one event each.
		{"type": "app.foreground", "data": map[string]any{"package": "w", "event": "resumed", "count": 9}},
	})
	before := snapshot(t, st)
	if len(before) < 10 {
		t.Fatalf("too few aggregates: %v", before)
	}
	// Migration 2 rebuilds with weight 1, migration 3 applies data.count.
	for _, m := range migrations[1:] {
		if _, err := st.w.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	after := snapshot(t, st)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("rebuild differs:\ningest  %v\nrebuild %v", before, after)
	}
}

// ingestOne ingests one event with an explicit ts (maybe very old), using the given reception time.
func ingestOne(t *testing.T, st *Store, now, ts time.Time, typ string, data map[string]any) IngestResult {
	t.Helper()
	ingestSeq++
	raw, _ := json.Marshal(map[string]any{"id": fmt.Sprintf("01JCQ8Z3K4M5N6P7Q8R9V%05d", ingestSeq), "ts": model.FormatTS(ts),
		"seq": ingestSeq, "boot_id": "b", "elapsed_ms": 1, "sev": 0, "type": typ, "data": data})
	e, err := model.ParseEvent(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	res, err := st.Ingest(context.Background(), "dev_1", "", []*model.Event{e}, now)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func topOf(t *testing.T, st *Store, kind string, from, to time.Time) map[string]int64 {
	t.Helper()
	items, err := st.StatsTop(context.Background(), "", kind, "", from.UnixMilli(), to.UnixMilli(), 100)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, it := range items {
		out[it.Key] = it.Count
	}
	return out
}

// /stats/top weights net.dns and net.connect by data.count; the timeline stays a count of events;
// late events (old ts) land in the hour of their ts, not in the hour of reception.
func TestTopWeightedByCountAndOldTS(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "vigie.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Date(2026, 11, 15, 22, 30, 0, 0, time.UTC)
	hourOld := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC) // two days before reception
	old := hourOld.Add(59*time.Minute + 59*time.Second)      // last second of its hour
	ingestOne(t, st, now, old, "net.dns", map[string]any{"package": "p", "hostname": "Late.Example.", "count": 25, "last_event_ts": model.FormatTS(old.Add(time.Hour))})
	ingestOne(t, st, now, old.Add(-time.Hour), "net.dns", map[string]any{"package": "p", "hostname": "late.example"})
	ingestOne(t, st, now, now.Add(-time.Minute), "net.dns", map[string]any{"package": "p", "hostname": "late.example", "count": 3})
	ingestOne(t, st, now, old, "net.connect", map[string]any{"package": "p", "ip": "1.2.3.4", "port": 443, "count": 8})
	ingestOne(t, st, now, old, "security.log", map[string]any{"tag": "x", "level": "error", "count": 4})

	// Only the old hour: 25, not the 1 + 3 of the other hours, and nothing in the reception hour.
	got := topOf(t, st, TopDNSHostname, hourOld, hourOld.Add(time.Hour-time.Millisecond))
	if len(got) != 1 || got["late.example"] != 25 {
		t.Fatalf("old hour: %v", got)
	}
	if got := topOf(t, st, TopDNSHostname, now.Add(-time.Hour), now); len(got) != 1 || got["late.example"] != 3 {
		t.Fatalf("reception hours: %v", got)
	}
	if got := topOf(t, st, TopDNSHostname, hourOld.Add(-24*time.Hour), now); got["late.example"] != 29 {
		t.Fatalf("whole range: %v", got)
	}
	if got := topOf(t, st, TopDNSPackage, hourOld.Add(-24*time.Hour), now); got["p"] != 29 {
		t.Fatalf("dns_package: %v", got)
	}
	if got := topOf(t, st, TopConnectDest, hourOld, hourOld.Add(time.Hour)); got["1.2.3.4:443"] != 8 {
		t.Fatalf("connect_dest: %v", got)
	}
	if got := topOf(t, st, TopConnectPackage, hourOld, hourOld.Add(time.Hour)); got["p"] != 8 {
		t.Fatalf("connect_package: %v", got)
	}
	// event_type counts events (one per event whatever data.count).
	types := topOf(t, st, TopEventType, hourOld, hourOld.Add(time.Hour-time.Millisecond))
	if types["net.dns"] != 1 || types["net.connect"] != 1 || types["security.log"] != 1 {
		t.Fatalf("event_type: %v", types)
	}
	tl, err := st.StatsTimeline(ctx, TimelineQuery{FromMS: hourOld.UnixMilli(), ToMS: hourOld.Add(time.Hour - time.Millisecond).UnixMilli(),
		BucketMS: hourMS, By: "type"})
	if err != nil {
		t.Fatal(err)
	}
	for _, sr := range tl.Series {
		for _, c := range sr.Counts {
			if c > 1 {
				t.Fatalf("timeline weighted by count: %+v", tl)
			}
		}
	}
}

// Events older than the retention window are acknowledged without being stored, and nothing is
// aggregated for them; weighted aggregates follow the purge by hour.
func TestRetentionWithOldTS(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "vigie.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Date(2026, 11, 15, 22, 30, 0, 0, time.UTC)
	st.SetRetention(90 * 24 * time.Hour)
	// 89 days old: kept, though far from the reception time. 91 days old: dropped.
	kept := ingestOne(t, st, now, now.Add(-89*24*time.Hour), "net.dns", map[string]any{"hostname": "kept.example", "count": 7})
	lost := ingestOne(t, st, now, now.Add(-91*24*time.Hour), "net.dns", map[string]any{"hostname": "lost.example", "count": 9})
	if len(kept.Stored) != 1 || kept.Expired != 0 || len(lost.Stored) != 0 || lost.Expired != 1 || lost.Duplicates != 0 {
		t.Fatalf("kept %+v lost %+v", kept, lost)
	}
	got := topOf(t, st, TopDNSHostname, now.Add(-200*24*time.Hour), now)
	if len(got) != 1 || got["kept.example"] != 7 {
		t.Fatalf("aggregates: %v", got)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM events WHERE data LIKE '%lost.example%'`); n != 0 {
		t.Fatalf("expired event stored: %d", n)
	}
	// The purge then removes the weighted aggregate of a no-longer-retained hour.
	st.SetRetention(0)
	ingestOne(t, st, now, now.Add(-100*24*time.Hour), "net.dns", map[string]any{"hostname": "ancient.example", "count": 50})
	if _, err := st.Purge(ctx, now.Add(-90*24*time.Hour), now, time.Hour); err != nil {
		t.Fatal(err)
	}
	got = topOf(t, st, TopDNSHostname, now.Add(-200*24*time.Hour), now)
	if len(got) != 1 || got["kept.example"] != 7 {
		t.Fatalf("after purge: %v", got)
	}
}

func countRows(t *testing.T, st *Store, q string) int {
	t.Helper()
	var n int
	if err := st.r.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
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
	if _, err := st.Ingest(context.Background(), "dev_1", "", []*model.Event{e}, time.Now()); err != nil {
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
