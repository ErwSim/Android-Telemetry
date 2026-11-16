// Package enroll creates devices and their enrollment file (contract §4).
package enroll

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/erwsim/watchpost/server/collector/internal/pki"
	"github.com/erwsim/watchpost/server/collector/internal/store"
)

// File is the content of a .watchpost enrollment file.
type File struct {
	Version        int    `json:"version"`
	IngestURL      string `json:"ingest_url"`
	DeviceID       string `json:"device_id"`
	DeviceName     string `json:"device_name"`
	DeviceToken    string `json:"device_token"`
	ClientCertPEM  string `json:"client_cert_pem"`
	ClientKeyPEM   string `json:"client_key_pem"`
	ServerCAPEM    string `json:"server_ca_pem,omitempty"`
	PrivateDNSHost string `json:"private_dns_host,omitempty"`
}

// Params are the inputs of Create.
type Params struct {
	Name           string
	IngestURL      string
	PrivateDNSHost string
	ServerCAPEM    string
}

// ValidName reports whether a device name is acceptable.
func ValidName(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(" _.-+()", r)) {
			return false
		}
	}
	return true
}

// CheckIngestURL validates the ingestion URL written in the file.
func CheckIngestURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid ingestion URL: %q (expected https://host[:port])", s)
	}
	return u, nil
}

// Create registers a new device and returns its enrollment file.
func Create(ctx context.Context, st *store.Store, ca *pki.CA, p Params, now time.Time) (*File, error) {
	if !ValidName(p.Name) {
		return nil, errors.New("invalid device name (1 to 64 letters, digits, spaces, \"_ . - + ( )\")")
	}
	if _, err := CheckIngestURL(p.IngestURL); err != nil {
		return nil, err
	}
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	deviceID := "dev_" + hex.EncodeToString(idBytes)
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	if !ValidDeviceID(deviceID) || !ValidToken(token) {
		return nil, errors.New("generated credentials do not match the format (contract §4)")
	}
	cert, err := ca.Issue(deviceID, now)
	if err != nil {
		return nil, fmt.Errorf("certificate issuance: %w", err)
	}
	tokenHash := HashToken(token)
	if err := st.CreateDevice(ctx, &store.Device{
		DeviceID: deviceID, Name: p.Name, TokenHash: tokenHash, CertSHA256: cert.SHA256,
		CertPEM: string(cert.CertPEM), EnrolledAt: now,
	}); err != nil {
		return nil, fmt.Errorf("device registration: %w", err)
	}
	return &File{
		Version: 1, IngestURL: strings.TrimRight(p.IngestURL, "/"), DeviceID: deviceID, DeviceName: p.Name,
		DeviceToken: token, ClientCertPEM: string(cert.CertPEM), ClientKeyPEM: string(cert.KeyPEM),
		ServerCAPEM: p.ServerCAPEM, PrivateDNSHost: p.PrivateDNSHost,
	}, nil
}

// ValidDeviceID reports whether id matches the contract §4 format: "dev_" followed by [a-z0-9], 64 characters at most.
func ValidDeviceID(id string) bool {
	rest, ok := strings.CutPrefix(id, "dev_")
	if !ok || rest == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// ValidToken reports whether t matches the contract §4 format: [A-Za-z0-9._~-], 128 characters at most.
func ValidToken(t string) bool {
	if t == "" || len(t) > 128 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._~-", c) >= 0) {
			return false
		}
	}
	return true
}

// newToken returns a random device token (256 bits, base64url without padding: within the §4 alphabet).
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Renew issues a new token and certificate for an existing device (same device_id, contract §4) and stores
// them as the pending pair: the current pair stays valid until the first authenticated request with the new
// one. A second Renew before that replaces the pending pair. Unknown or revoked devices are refused
// (store.ErrNotFound, store.ErrRevoked). The returned file is not yet written: the caller does it, and a
// failure leaves the device usable with its current pair.
func Renew(ctx context.Context, st *store.Store, ca *pki.CA, deviceID string, p Params, now time.Time) (*File, error) {
	if _, err := CheckIngestURL(p.IngestURL); err != nil {
		return nil, err
	}
	if !ValidDeviceID(deviceID) {
		return nil, store.ErrNotFound
	}
	dev, err := st.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if dev.Revoked() {
		return nil, store.ErrRevoked
	}
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	cert, err := ca.Issue(deviceID, now)
	if err != nil {
		return nil, fmt.Errorf("certificate issuance: %w", err)
	}
	if err := st.SetPendingCredentials(ctx, deviceID, HashToken(token), cert.SHA256, string(cert.CertPEM), now); err != nil {
		return nil, err
	}
	return &File{
		Version: 1, IngestURL: strings.TrimRight(p.IngestURL, "/"), DeviceID: deviceID, DeviceName: dev.Name,
		DeviceToken: token, ClientCertPEM: string(cert.CertPEM), ClientKeyPEM: string(cert.KeyPEM),
		ServerCAPEM: p.ServerCAPEM, PrivateDNSHost: p.PrivateDNSHost,
	}, nil
}

// Write writes the file with mode 0600, refusing to overwrite unless force.
func (f *File) Write(path string, force bool) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	fh, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	// An existing file keeps its mode when truncated: restrict it before writing secrets.
	if err := fh.Chmod(0o600); err != nil {
		fh.Close()
		return err
	}
	if _, err := fh.Write(b); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

// Read loads an enrollment file.
func Read(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", path, err)
	}
	if f.Version != 1 || f.DeviceID == "" || f.DeviceToken == "" {
		return nil, fmt.Errorf("%s: enrollment file incomplete or of unknown version", path)
	}
	return &f, nil
}
