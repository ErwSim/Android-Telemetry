package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCAAndClientCert(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	now := time.Now()
	ca, created, err := LoadOrCreate(dir, now)
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	if st, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode: %v %v", st.Mode(), err)
	}
	if !ca.Cert.IsCA || ca.Cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatal("CA attributes")
	}
	if pub, ok := ca.Cert.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Fatal("CA key is not P-256")
	}
	// Second load reuses the same CA.
	ca2, created, err := LoadOrCreate(dir, now)
	if err != nil || created || !ca2.Cert.Equal(ca.Cert) {
		t.Fatalf("reload: %v %v", created, err)
	}

	cc, err := ca.Issue("dev_0123456789abcdef", now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(cc.CertPEM)
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "dev_0123456789abcdef" {
		t.Fatalf("CN %q", cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || cert.IsCA {
		t.Fatal("client certificate usage")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("chain: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("client certificate must not be valid for server auth")
	}
	kb, _ := pem.Decode(cc.KeyPEM)
	if kb.Type != "PRIVATE KEY" {
		t.Fatalf("key PEM type %q (PKCS#8 expected)", kb.Type)
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !k.(*ecdsa.PrivateKey).PublicKey.Equal(cert.PublicKey) {
		t.Fatal("key does not match certificate")
	}
	fp, err := FingerprintPEM(cc.CertPEM)
	if err != nil || fp != cc.SHA256 || len(fp) != 64 {
		t.Fatalf("fingerprint %q %v", fp, err)
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	withColons := ""
	for i := 0; i < 64; i += 2 {
		if i > 0 {
			withColons += ":"
		}
		withColons += "AB"
	}
	if NormalizeFingerprint(withColons) != fp || NormalizeFingerprint(" "+fp+" ") != fp {
		t.Fatal("normalize")
	}
	if NormalizeFingerprint("zz") != "" || NormalizeFingerprint(strings.Repeat("g", 64)) != "" {
		t.Fatal("invalid accepted")
	}
}

func TestLoadRejectsMismatchedKey(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	if _, _, err := LoadOrCreate(d1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(d2, time.Now()); err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(filepath.Join(d2, "ca.key"))
	if err := os.WriteFile(filepath.Join(d1, "ca.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(d1); err == nil {
		t.Fatal("mismatched key accepted")
	}
}
