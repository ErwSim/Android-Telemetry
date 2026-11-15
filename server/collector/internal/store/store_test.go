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
