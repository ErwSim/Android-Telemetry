package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
)

// The usage_counts rebuild of migration 5 gives the same counters as the ingestion.
func TestMigration5UsageBackfill(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	raw := []byte(`{"id":"` + model.NewULID(now) + `","ts":"` + model.FormatTS(now) + `","seq":1,"boot_id":"b","elapsed_ms":1,"type":"net.usage","sev":0,"data":{"apps":[{"package":"p","rx_bytes":10,"tx_bytes":3},{"package":"p","rx_bytes":5,"tx_bytes":1}]}}`)
	ev, err := model.ParseEvent(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.w.ExecContext(ctx, `INSERT INTO devices(device_id,name,token_hash,cert_sha256,cert_pem,enrolled_ms) VALUES('d','d',x'00','','',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Ingest(ctx, "d", "", []*model.Event{ev}, now); err != nil {
		t.Fatal(err)
	}
	b1, _ := st.UsageBytes(ctx, "d", 0, now.UnixMilli()+1)
	st.w.ExecContext(ctx, `DELETE FROM usage_counts`)
	m := migrations[4]
	i := strings.Index(m, "INSERT INTO usage_counts")
	if _, err := st.w.ExecContext(ctx, m[i:]); err != nil {
		t.Fatal(err)
	}
	b2, _ := st.UsageBytes(ctx, "d", 0, now.UnixMilli()+1)
	if b1["p"] != b2["p"] || b1["p"].Rx != 15 || b1["p"].Tx != 4 {
		t.Fatalf("%v %v", b1, b2)
	}
}
