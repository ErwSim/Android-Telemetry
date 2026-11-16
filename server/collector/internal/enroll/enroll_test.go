package enroll

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/pki"
	"github.com/erwsim/watchpost/server/collector/internal/store"
)

func TestCreateWriteRead(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(dir, "watchpost.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ca, _, err := pki.LoadOrCreate(filepath.Join(dir, "pki"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(ctx, st, ca, Params{Name: "", IngestURL: "https://x"}, time.Now()); err == nil {
		t.Fatal("empty name accepted")
	}
	if _, err := Create(ctx, st, ca, Params{Name: "s25", IngestURL: "ftp://x"}, time.Now()); err == nil {
		t.Fatal("bad URL accepted")
	}
	f, err := Create(ctx, st, ca, Params{Name: "Galaxy S25+", IngestURL: "https://ingest.example.org/", PrivateDNSHost: "dns.example.org"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || len(f.DeviceID) != 20 || f.IngestURL != "https://ingest.example.org" || f.ServerCAPEM != "" {
		t.Fatalf("%+v", f)
	}
	dev, err := st.GetDevice(ctx, f.DeviceID)
	if err != nil || !bytes.Equal(dev.TokenHash, HashToken(f.DeviceToken)) {
		t.Fatal("token hash not stored")
	}
	fp, _ := pki.FingerprintPEM([]byte(f.ClientCertPEM))
	if dev.CertSHA256 != fp {
		t.Fatal("fingerprint not stored")
	}
	path := filepath.Join(dir, "s25.watchpost")
	if err := f.Write(path, false); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if err := f.Write(path, false); err == nil {
		t.Fatal("overwrote existing file")
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("server_ca_pem")) {
		t.Fatal("empty optional field written")
	}
	g, err := Read(path)
	if err != nil || g.DeviceToken != f.DeviceToken || g.PrivateDNSHost != "dns.example.org" {
		t.Fatalf("read back: %v", err)
	}
}

// Regression: --force rewrote an existing file in place and kept its mode, so
// the device token and private key could land in a world-readable file.
func TestWriteForceKeepsSecretsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s25.watchpost")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	f := &File{Version: 1, DeviceID: "dev_1", DeviceToken: "secret"}
	if err := f.Write(path, false); err == nil {
		t.Fatal("existing file overwritten without force")
	}
	if err := f.Write(path, true); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v after --force", fi.Mode().Perm())
	}
	if g, err := Read(path); err != nil || g.DeviceToken != "secret" {
		t.Fatalf("%+v %v", g, err)
	}
}

func newTestStore(t *testing.T) (*store.Store, *pki.CA) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "watchpost.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ca, _, err := pki.LoadOrCreate(filepath.Join(dir, "pki"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return st, ca
}

// Contract §4 formats, checked on what is really generated (many draws) and on the validators.
func TestGeneratedFormats(t *testing.T) {
	st, ca := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 200; i++ {
		f, err := Create(ctx, st, ca, Params{Name: "d", IngestURL: "https://x.example"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !ValidDeviceID(f.DeviceID) || !ValidToken(f.DeviceToken) {
			t.Fatalf("format: %q %q", f.DeviceID, f.DeviceToken)
		}
		r, err := Renew(ctx, st, ca, f.DeviceID, Params{IngestURL: "https://x.example"}, time.Now())
		if err != nil || !ValidToken(r.DeviceToken) || r.DeviceID != f.DeviceID {
			t.Fatalf("renew format: %v %+v", err, r)
		}
	}
	for _, ok := range []string{"dev_8f3a", "dev_" + strings.Repeat("a", 60)} {
		if !ValidDeviceID(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "dev_", "DEV_a", "dev_A", "dev_a-b", "dev_a b", "dev_é", "x_abc", "dev_" + strings.Repeat("a", 61)} {
		if ValidDeviceID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, ok := range []string{"aZ09._~-", strings.Repeat("a", 128)} {
		if !ValidToken(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "a b", "a+b", "a/b", "a=b", "é", "a\n", strings.Repeat("a", 129)} {
		if ValidToken(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRenew(t *testing.T) {
	st, ca := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	p := Params{IngestURL: "https://ingest.example.org/", PrivateDNSHost: "dns.example.org"}
	if _, err := Renew(ctx, st, ca, "dev_ffff", p, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := Renew(ctx, st, ca, "../etc", p, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
	f, err := Create(ctx, st, ca, Params{Name: "Galaxy S25+", IngestURL: "https://ingest.example.org"}, now)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Renew(ctx, st, ca, f.DeviceID, p, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if r.DeviceID != f.DeviceID || r.DeviceName != "Galaxy S25+" || r.DeviceToken == f.DeviceToken ||
		r.ClientCertPEM == f.ClientCertPEM || r.ClientKeyPEM == f.ClientKeyPEM || r.IngestURL != "https://ingest.example.org" || r.PrivateDNSHost != "dns.example.org" {
		t.Fatalf("renewed file: %+v", r)
	}
	fp, _ := pki.FingerprintPEM([]byte(r.ClientCertPEM))
	dev, _ := st.GetDevice(ctx, f.DeviceID)
	// The current pair is untouched, the new one is stored (token hashed, never in clear) as pending.
	if !bytes.Equal(dev.TokenHash, HashToken(f.DeviceToken)) || !bytes.Equal(dev.NextTokenHash, HashToken(r.DeviceToken)) ||
		dev.NextCertSHA256 != fp || dev.NextCertPEM != r.ClientCertPEM || bytes.Contains(dev.NextTokenHash, []byte(r.DeviceToken)) {
		t.Fatalf("stored: %+v", dev)
	}
	// The renewed certificate is a fresh 2-year one for the same CN.
	exp, err := pki.NotAfterPEM([]byte(r.ClientCertPEM))
	if err != nil || exp.Before(now.Add(2*365*24*time.Hour-48*time.Hour)) {
		t.Fatalf("expiry %v %v", exp, err)
	}
	// Second renewal replaces the pending pair.
	r2, err := Renew(ctx, st, ca, f.DeviceID, p, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeviceByTokenHash(ctx, HashToken(r.DeviceToken)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("first pending token survived a second renewal")
	}
	if d, err := st.DeviceByTokenHash(ctx, HashToken(r2.DeviceToken)); err != nil || !d.ViaPending {
		t.Fatalf("second pending: %v", err)
	}
	// Revoked devices cannot be renewed.
	if err := st.RevokeDevice(ctx, f.DeviceID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Renew(ctx, st, ca, f.DeviceID, p, now); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	// The renewed file is written 0600 like any other.
	path := filepath.Join(t.TempDir(), "r.watchpost")
	if err := r2.Write(path, false); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}
