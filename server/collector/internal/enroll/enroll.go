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

	"github.com/erwsim/android-telemetry/server/collector/internal/pki"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

// File is the content of a .vigie enrollment file.
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
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(" _.-", r)) {
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
		return nil, fmt.Errorf("URL d'ingestion invalide : %q (attendu https://hôte[:port])", s)
	}
	return u, nil
}

// Create registers a new device and returns its enrollment file.
func Create(ctx context.Context, st *store.Store, ca *pki.CA, p Params, now time.Time) (*File, error) {
	if !ValidName(p.Name) {
		return nil, errors.New("nom d'appareil invalide (1 à 64 lettres, chiffres, espaces, « _ . - »)")
	}
	if _, err := CheckIngestURL(p.IngestURL); err != nil {
		return nil, err
	}
	idBytes := make([]byte, 8)
	tokBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	if _, err := rand.Read(tokBytes); err != nil {
		return nil, err
	}
	deviceID := "dev_" + hex.EncodeToString(idBytes)
	token := base64.RawURLEncoding.EncodeToString(tokBytes)
	cert, err := ca.Issue(deviceID, now)
	if err != nil {
		return nil, fmt.Errorf("émission du certificat : %w", err)
	}
	tokenHash := HashToken(token)
	if err := st.CreateDevice(ctx, &store.Device{
		DeviceID: deviceID, Name: p.Name, TokenHash: tokenHash, CertSHA256: cert.SHA256,
		CertPEM: string(cert.CertPEM), EnrolledAt: now,
	}); err != nil {
		return nil, fmt.Errorf("enregistrement de l'appareil : %w", err)
	}
	return &File{
		Version: 1, IngestURL: strings.TrimRight(p.IngestURL, "/"), DeviceID: deviceID, DeviceName: p.Name,
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
		return nil, fmt.Errorf("%s : JSON invalide : %w", path, err)
	}
	if f.Version != 1 || f.DeviceID == "" || f.DeviceToken == "" {
		return nil, fmt.Errorf("%s : fichier d'enrôlement incomplet ou de version inconnue", path)
	}
	return &f, nil
}
