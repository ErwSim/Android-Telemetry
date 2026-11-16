// Package pki manages the private client CA of the collector (contract §4):
// an ECDSA P-256 CA created on first start, and one client certificate per
// device (CN=<device_id>, extended key usage clientAuth).
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	caValidity     = 20 * 365 * 24 * time.Hour
	clientValidity = 2 * 365 * 24 * time.Hour
	backdate       = 5 * time.Minute
)

// CA is the loaded client certificate authority.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey
}

// Paths of the CA files inside dir.
func certPath(dir string) string { return filepath.Join(dir, "ca.crt") }
func keyPath(dir string) string  { return filepath.Join(dir, "ca.key") }

// LoadOrCreate loads the CA from dir, creating it if absent.
func LoadOrCreate(dir string, now time.Time) (*CA, bool, error) {
	ca, err := Load(dir)
	if err == nil {
		return ca, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	if err := create(dir, now); err != nil {
		if errors.Is(err, os.ErrExist) { // created concurrently by another process
			ca, err := Load(dir)
			return ca, false, err
		}
		return nil, false, err
	}
	ca, err = Load(dir)
	return ca, err == nil, err
}

// Load reads the CA from dir.
func Load(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath(dir))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath(dir))
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s : PEM de certificat invalide", certPath(dir))
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s : %w", certPath(dir), err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s : PEM de clé PKCS#8 invalide", keyPath(dir))
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s : %w", keyPath(dir), err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("%s : la clé ne correspond pas au certificat de l'AC", keyPath(dir))
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

func create(dir string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ski := subjectKeyID(&key.PublicKey)
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "Watchpost Client CA", Organization: []string{"Watchpost"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	// Key first, exclusively: a concurrent creator fails with ErrExist.
	if err := writeExclusive(keyPath(dir), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := writeExclusive(certPath(dir), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		os.Remove(keyPath(dir))
		return err
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Link(tmp.Name(), path) // fails with ErrExist if path exists
}

// ClientCert is an issued device certificate and its private key.
type ClientCert struct {
	CertPEM []byte
	KeyPEM  []byte // PKCS#8
	SHA256  string // hex SHA-256 of the DER certificate
}

// Issue creates a client certificate for deviceID.
func (ca *CA) Issue(deviceID string, now time.Time) (*ClientCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(clientValidity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: deviceID, Organization: []string{"Watchpost"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		AuthorityKeyId:        ca.Cert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &ClientCert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		SHA256:  Fingerprint(der),
	}, nil
}

// Fingerprint returns the lowercase hex SHA-256 of a DER certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// FingerprintPEM returns the fingerprint of the first certificate in a PEM block.
func FingerprintPEM(certPEM []byte) (string, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil || b.Type != "CERTIFICATE" {
		return "", errors.New("certificat PEM invalide")
	}
	return Fingerprint(b.Bytes), nil
}

// NotAfterPEM returns the expiry date of a PEM certificate.
func NotAfterPEM(certPEM []byte) (time.Time, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil || b.Type != "CERTIFICATE" {
		return time.Time{}, errors.New("certificat PEM invalide")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter.UTC(), nil
}

// NormalizeFingerprint lowercases a hex fingerprint and removes ':' separators,
// returning "" when the value is not 64 hex characters.
func NormalizeFingerprint(s string) string {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	if len(s) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
}

func subjectKeyID(pub *ecdsa.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(b)
	return sum[:20]
}
