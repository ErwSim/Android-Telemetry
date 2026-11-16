package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
)

func parseEv(t *testing.T, ts time.Time, typ, data string) *model.Event {
	t.Helper()
	raw := fmt.Sprintf(`{"id":%q,"ts":%q,"seq":1,"boot_id":"b","elapsed_ms":1,"type":%q,"sev":0,"data":%s}`, model.NewULID(ts), model.FormatTS(ts), typ, data)
	ev, err := model.ParseEvent([]byte(raw), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func dump(t *testing.T, st *Store, q string) []string {
	t.Helper()
	rows, err := st.r.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		parts := make([]string, len(vals))
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			parts[i] = fmt.Sprint(v)
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

// The aggregates of migrations 6 and 7 (ops_counts, app_latest) are those of the ingestion; the hours of the
// detection inputs are marked to be evaluated, late batches included.
func TestMigration6DetectionAggregates(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.w.ExecContext(ctx, `INSERT INTO devices(device_id,name,token_hash,cert_sha256,cert_pem,enrolled_ms) VALUES('d','d',x'00','','',0)`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	evs := []*model.Event{
		parseEv(t, now.Add(time.Minute), "app.ops", `{"apps":[{"package":"p","op":"send_sms","count":5,"background_count":4,"last_ts":"`+model.FormatTS(now.Add(50*time.Second))+`"},
			{"package":"p","op":"send_sms","count":2,"background_count":-3,"rejected_count":40},{"package":"q","op":"camera","count":1.5},{"op":"camera","count":1},"x"]}`),
		parseEv(t, now.Add(2*time.Minute), "app.ops", `{"apps":[{"package":"p","op":"send_sms","count":1,"background_count":1}]}`),
		parseEv(t, now.Add(3*time.Minute), "app.risk", `{"package":"p","score":10,"level":"low","reasons":[]}`),
		parseEv(t, now.Add(4*time.Minute), "app.risk", `{"package":"p","score":80,"level":"high","reasons":["sideloaded"]}`),
		parseEv(t, now.Add(time.Minute), "app.risk", `{"package":"q","score":5,"level":"low"}`),
		parseEv(t, now.Add(5*time.Minute), "app.role", `{"role":"sms","old":"a","new":"b"}`),
		parseEv(t, now.Add(-72*time.Hour), "net.connect", `{"package":"p","ip":"192.0.2.1","port":443}`), // late batch
		parseEv(t, now.Add(6*time.Minute), "device.screen", `{"state":"on"}`),                            // not an input
	}
	if _, err := st.Ingest(ctx, "d", "", evs, time.Now()); err != nil {
		t.Fatal(err)
	}
	opsQ := `SELECT device_id, hour_ms, package, op, count, bg_count, rej_count, last_ms FROM ops_counts ORDER BY 1,2,3,4`
	latestQ := `SELECT device_id, kind, key, ts_ms, data FROM app_latest ORDER BY 1,2,3`
	ops1, latest1 := dump(t, st, opsQ), dump(t, st, latestQ)
	if len(ops1) != 2 || !strings.Contains(ops1[0], " p send_sms 8 5 40 ") || !strings.Contains(ops1[1], " q camera 0 0 0") {
		t.Fatalf("ops %v", ops1)
	}
	if len(latest1) != 3 || !strings.Contains(latest1[0], `"score":80`) || !strings.HasPrefix(latest1[2], "d role sms") {
		t.Fatalf("latest %v", latest1)
	}
	dirty, err := st.DirtyHours(ctx, 10)
	if err != nil || len(dirty) != 2 || dirty[0].HourMS != now.Add(-72*time.Hour).UnixMilli() || dirty[1].HourMS != now.UnixMilli() {
		t.Fatalf("dirty %+v %v", dirty, err)
	}
	// Re-marked while being evaluated: kept.
	if _, err := st.Ingest(ctx, "d", "", []*model.Event{parseEv(t, now.Add(7*time.Minute), "net.dns", `{"package":"p","hostname":"a.example"}`)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearDirty(ctx, dirty); err != nil {
		t.Fatal(err)
	}
	if left, _ := st.DirtyHours(ctx, 10); len(left) != 1 || left[0].HourMS != now.UnixMilli() {
		t.Fatalf("left %+v", left)
	}

	m := migrations[5]
	part := func(from, to string) string { return m[strings.Index(m, from):strings.Index(m, to)] }
	if _, err := st.w.ExecContext(ctx, `DELETE FROM ops_counts; DELETE FROM app_latest; DELETE FROM detect_dirty;`); err != nil {
		t.Fatal(err)
	}
	m7 := migrations[6]
	for _, q := range []string{m7[strings.Index(m7, "INSERT INTO ops_counts"):], part("INSERT INTO app_latest", "CREATE TABLE detections"),
		m[strings.Index(m, "INSERT OR IGNORE INTO detect_dirty"):]} {
		if _, err := st.w.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	// last_ms: the SQL conversion of the date may differ by a millisecond of rounding; compare the rest.
	trim := func(rows []string) []string {
		out := make([]string, len(rows))
		for i, r := range rows {
			out[i] = r[:strings.LastIndex(r, " ")]
		}
		return out
	}
	if ops2 := dump(t, st, opsQ); !reflect.DeepEqual(trim(ops1), trim(ops2)) {
		t.Fatalf("ops rebuilt %v, ingested %v", ops2, ops1)
	}
	if latest2 := dump(t, st, latestQ); !reflect.DeepEqual(latest1, latest2) {
		t.Fatalf("latest rebuilt %v, ingested %v", latest2, latest1)
	}
	// The migration marks the last two days of inputs (here the current hour; the late batch is older).
	if d, _ := st.DirtyHours(ctx, 10); len(d) != 1 || d[0].HourMS != now.UnixMilli() {
		t.Fatalf("seeded dirty %+v", d)
	}
}

// A finding is stored once per device, type, subject and window, with its event of the collector; a later
// evaluation updates it in place, and is exported again only when more severe or with a new element, at
// most once an hour.
func TestUpsertDetections(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	d := Detection{DeviceID: "d", Type: "detect.threat_domain", Subject: "p", WindowFromMS: 3600000, WindowToMS: 7200000, Package: "p", Sev: 2,
		Summary: "s", Evidence: map[string]any{"requests": 2}, Items: []string{"a.example"}}
	res, err := st.UpsertDetections(ctx, []Detection{d, d}, now)
	if err != nil || res.Added != 1 || len(res.Events) != 1 || res.Events[0].Source != "server" || res.Events[0].Type != "detect.threat_domain" {
		t.Fatalf("%+v %v", res, err)
	}
	id := res.Events[0].ID
	if res, _ := st.UpsertDetections(ctx, []Detection{d}, now); res.Added+res.Updated+len(res.Events) != 0 {
		t.Fatalf("identical: %+v", res)
	}
	// More of the same: updated in place, not exported again.
	d.Evidence = map[string]any{"requests": 40}
	if res, _ := st.UpsertDetections(ctx, []Detection{d}, now.Add(2*time.Hour)); res.Updated != 1 || len(res.Events) != 0 {
		t.Fatalf("counts only: %+v", res)
	}
	// A new domain within the hour after the last export: updated, export held back.
	d.Items = []string{"b.example"}
	if res, _ := st.UpsertDetections(ctx, []Detection{d}, now.Add(30*time.Minute)); res.Updated != 1 || len(res.Events) != 0 {
		t.Fatalf("held back: %+v", res)
	}
	// Later, the window is evaluated again (nothing new since): the held-back element is exported then.
	d.Evidence = map[string]any{"requests": 41}
	res, _ = st.UpsertDetections(ctx, []Detection{d}, now.Add(2*time.Hour))
	if res.Updated != 1 || len(res.Events) != 1 {
		t.Fatalf("export of the new element: %+v", res)
	}
	var data map[string]any
	_ = json.Unmarshal(res.Events[0].Data, &data)
	if data["update"] != true || data["detection_id"] != id {
		t.Fatalf("update event %v", data)
	}
	// A lower severity never lowers the stored one; a higher one is exported (after the hour).
	d.Sev, d.Evidence = 1, map[string]any{"requests": 42}
	if res, _ := st.UpsertDetections(ctx, []Detection{d}, now.Add(4*time.Hour)); len(res.Events) != 0 {
		t.Fatalf("lower severity exported: %+v", res)
	}
	d.Sev, d.Evidence = 3, map[string]any{"requests": 43}
	if res, _ := st.UpsertDetections(ctx, []Detection{d}, now.Add(4*time.Hour)); len(res.Events) != 1 || res.Events[0].Sev != 3 {
		t.Fatalf("higher severity: %+v", res)
	}
	items, more, err := st.ListDetections(ctx, DetectionQuery{FromMS: 0, ToMS: now.UnixMilli() + 1, Limit: 10, Package: "p"})
	if err != nil || more || len(items) != 1 || items[0].ID != id || items[0].Severity != 3 || string(items[0].Evidence) != `{"requests":43}` || items[0].UpdatedAt == "" {
		t.Fatalf("%+v %v", items, err)
	}
	if items, _, _ := st.ListDetections(ctx, DetectionQuery{FromMS: 0, ToMS: now.UnixMilli() + 1, Limit: 10, Package: "q"}); len(items) != 0 {
		t.Fatal("package filter")
	}
	d.WindowFromMS += 3600000
	if res, _ := st.UpsertDetections(ctx, []Detection{d}, now); res.Added != 1 {
		t.Fatal("next window")
	}
	// Retention: a detection whose window and finding time are both past the cutoff is purged.
	if _, err := st.Purge(ctx, time.Now().Add(time.Hour), time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if items, _, _ := st.ListDetections(ctx, DetectionQuery{FromMS: 0, ToMS: time.Now().UnixMilli() + 1, Limit: 10}); len(items) != 0 {
		t.Fatalf("after purge %+v", items)
	}
}
