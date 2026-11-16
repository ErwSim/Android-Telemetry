package sim

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/enroll"
	"github.com/erwsim/watchpost/server/collector/internal/pki"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a ULID for timestamp t.
func NewULID(t time.Time, rng *rand.Rand) string {
	ms := uint64(t.UnixMilli())
	var b [16]byte
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	for i := 6; i < 16; i++ {
		b[i] = byte(rng.Intn(256))
	}
	// 128 bits -> 26 base32 characters (first character holds 3 bits).
	var out [26]byte
	var acc uint64
	bits := 0
	idx := 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(b[i]) << bits
		bits += 8
		for bits >= 5 && idx > 0 {
			out[idx] = crockford[acc&31]
			acc >>= 5
			bits -= 5
			idx--
		}
	}
	out[0] = crockford[acc&31]
	return string(out[:])
}

// Client sends batches to the ingestion API like the agent does.
type Client struct {
	base       string
	deviceID   string
	token      string
	version    string
	certFP     string
	certHeader bool
	http       *http.Client
}

// NewClient builds a client from an enrollment file. When the URL is plain
// http (development, collector reached directly), the client also sets the
// certificate fingerprint header itself; the collector only believes it when
// the request comes from a trusted proxy address (127.0.0.1 by default).
func NewClient(f *enroll.File, url, version string) (*Client, error) {
	if url == "" {
		url = f.IngestURL
	}
	if _, err := enroll.CheckIngestURL(url); err != nil {
		return nil, err
	}
	fp, err := pki.FingerprintPEM([]byte(f.ClientCertPEM))
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if strings.HasPrefix(url, "https://") {
		cert, err := tls.X509KeyPair([]byte(f.ClientCertPEM), []byte(f.ClientKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		if f.ServerCAPEM != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(f.ServerCAPEM)) {
				return nil, fmt.Errorf("invalid server_ca_pem")
			}
			cfg.RootCAs = pool
		}
		tr.TLSClientConfig = cfg
	}
	return &Client{
		base: strings.TrimRight(url, "/"), deviceID: f.DeviceID, token: f.DeviceToken, version: version,
		certFP: fp, certHeader: strings.HasPrefix(url, "http://"),
		http: &http.Client{Transport: tr, Timeout: 60 * time.Second},
	}, nil
}

// Result is the ingestion answer.
type Result struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Rejected   []struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	} `json:"rejected"`
	ServerTime string `json:"server_time"`
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", "watchpost-sim/"+c.version)
	if c.certHeader {
		req.Header.Set("X-Watchpost-Client-Cert-Sha256", c.certFP)
	}
	return req, nil
}

// Ping calls GET /api/v1/ping.
func (c *Client) Ping(ctx context.Context) error {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/v1/ping", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ping: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// Send posts one batch (≤ 500 events), retrying on 429/5xx and network errors.
func (c *Client) Send(ctx context.Context, evs []Event) (*Result, error) {
	payload, err := json.Marshal(map[string]any{
		"device_id": c.deviceID, "agent_version": c.version, "sent_at": time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"), "events": evs,
	})
	if err != nil {
		return nil, err
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(payload)
	_ = zw.Close()

	backoff := time.Second
	for attempt := 1; ; attempt++ {
		req, err := c.newRequest(ctx, http.MethodPost, "/api/v1/ingest", bytes.NewReader(gz.Bytes()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		resp, err := c.http.Do(req)
		var wait time.Duration
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			switch {
			case resp.StatusCode == http.StatusOK:
				var r Result
				if err := json.Unmarshal(body, &r); err != nil {
					return nil, fmt.Errorf("unreadable response: %w", err)
				}
				return &r, nil
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
				if s, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && s > 0 {
					wait = time.Duration(s) * time.Second
				}
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			default:
				return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
		}
		if attempt >= 8 {
			return nil, err
		}
		if wait == 0 {
			wait = backoff
			backoff = min(backoff*2, 30*time.Second)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}
