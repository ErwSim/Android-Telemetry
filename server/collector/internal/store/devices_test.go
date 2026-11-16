package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newDev(t *testing.T, st *Store, id string) {
	t.Helper()
	if err := st.CreateDevice(context.Background(), &Device{DeviceID: id, Name: "s25", TokenHash: []byte("tok-" + id),
		CertSHA256: "cert-" + id, CertPEM: "pem", EnrolledAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestPendingCredentialsLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "vigie.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	newDev(t, st, "dev_a")
	if err := st.SetPendingCredentials(ctx, "dev_unknown", []byte("x"), "c", "p", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if err := st.SetPendingCredentials(ctx, "dev_a", []byte("n1"), "cn1", "pn1", now); err != nil {
		t.Fatal(err)
	}
	// Both tokens find the device; ViaPending tells which.
	d, err := st.DeviceByTokenHash(ctx, []byte("tok-dev_a"))
	if err != nil || d.ViaPending || !d.HasPending() {
		t.Fatalf("old: %+v %v", d, err)
	}
	d, err = st.DeviceByTokenHash(ctx, []byte("n1"))
	if err != nil || !d.ViaPending || d.NextCertSHA256 != "cn1" {
		t.Fatalf("new: %+v %v", d, err)
	}
	// A second renewal replaces the pending pair: the first one is gone.
	if err := st.SetPendingCredentials(ctx, "dev_a", []byte("n2"), "cn2", "pn2", now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeviceByTokenHash(ctx, []byte("n1")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replaced pending token still known: %v", err)
	}
	// Promotion: atomic, once; a stale token does nothing.
	if ok, err := st.PromotePending(ctx, "dev_a", []byte("n1")); err != nil || ok {
		t.Fatalf("stale promote: %v %v", ok, err)
	}
	if ok, err := st.PromotePending(ctx, "dev_a", []byte("n2")); err != nil || !ok {
		t.Fatalf("promote: %v %v", ok, err)
	}
	if ok, _ := st.PromotePending(ctx, "dev_a", []byte("n2")); ok {
		t.Fatal("second promotion reported a switch")
	}
	d, _ = st.GetDevice(ctx, "dev_a")
	if !bytes.Equal(d.TokenHash, []byte("n2")) || d.CertSHA256 != "cn2" || d.CertPEM != "pn2" || d.HasPending() || d.NextIssuedAt != nil {
		t.Fatalf("after promotion: %+v", d)
	}
	if _, err := st.DeviceByTokenHash(ctx, []byte("tok-dev_a")); !errors.Is(err, ErrNotFound) {
		t.Fatal("old token still known")
	}
	// Revocation drops the pending pair and forbids renewal and promotion.
	if err := st.SetPendingCredentials(ctx, "dev_a", []byte("n3"), "cn3", "pn3", now); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeDevice(ctx, "dev_a", now); err != nil {
		t.Fatal(err)
	}
	d, _ = st.GetDevice(ctx, "dev_a")
	if !d.Revoked() || d.HasPending() {
		t.Fatalf("revoked: %+v", d)
	}
	if err := st.SetPendingCredentials(ctx, "dev_a", []byte("n4"), "c", "p", now); !errors.Is(err, ErrRevoked) {
		t.Fatalf("renew revoked: %v", err)
	}
	if ok, _ := st.PromotePending(ctx, "dev_a", []byte("n3")); ok {
		t.Fatal("promoted on a revoked device")
	}
}

// A database created by a binary that predates migration 4 keeps its devices and gains renewal.
func TestMigration4OnExistingDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vigie.db")
	if err := restrictFiles(path); err != nil {
		t.Fatal(err)
	}
	st := &Store{path: path}
	var err error
	if st.w, err = openRaw(path); err != nil {
		t.Fatal(err)
	}
	for i, m := range migrations[:3] {
		if _, err := st.w.Exec(m); err != nil {
			t.Fatalf("migration %d: %v", i+1, err)
		}
	}
	if _, err := st.w.Exec(`PRAGMA user_version = 3`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.w.Exec(`INSERT INTO devices(device_id, name, token_hash, cert_sha256, cert_pem, enrolled_ms) VALUES('dev_old','s25',x'0102','fp','pem',1000)`); err != nil {
		t.Fatal(err)
	}
	st.w.Close()

	st, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var v int
	_ = st.w.QueryRow("PRAGMA user_version").Scan(&v)
	if v != SchemaVersion || v < 4 {
		t.Fatalf("user_version %d", v)
	}
	d, err := st.GetDevice(ctx, "dev_old")
	if err != nil || d.HasPending() || d.CertSHA256 != "fp" || !bytes.Equal(d.TokenHash, []byte{1, 2}) {
		t.Fatalf("device after migration: %+v %v", d, err)
	}
	if d, err := st.DeviceByTokenHash(ctx, []byte{1, 2}); err != nil || d.ViaPending {
		t.Fatalf("lookup after migration: %+v %v", d, err)
	}
	if err := st.SetPendingCredentials(ctx, "dev_old", []byte{3}, "fp2", "pem2", time.Now()); err != nil {
		t.Fatal(err)
	}
}

func openRaw(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
