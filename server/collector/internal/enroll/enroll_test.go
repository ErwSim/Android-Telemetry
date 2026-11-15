package enroll

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/pki"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

func TestCreateWriteRead(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(dir, "vigie.db"))
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
	path := filepath.Join(dir, "s25.vigie")
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
	path := filepath.Join(t.TempDir(), "s25.vigie")
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
