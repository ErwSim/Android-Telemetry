package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/config"
)

// AlertsClient reads Watchpost alerts from the Wazuh indexer (OpenSearch).
type AlertsClient struct {
	base     *url.URL
	user     string
	password string
	http     *http.Client
}

// NewAlertsClient returns a client, or a disabled client when no URL is configured.
func NewAlertsClient(cfg *config.Config) (*AlertsClient, error) {
	if cfg.WazuhIndexerURL == "" {
		return &AlertsClient{}, nil
	}
	u, err := url.Parse(strings.TrimRight(cfg.WazuhIndexerURL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("invalid WATCHPOST_WAZUH_INDEXER_URL")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.WazuhIndexerCAFile != "" {
		pem, err := os.ReadFile(cfg.WazuhIndexerCAFile)
		if err != nil {
			return nil, fmt.Errorf("WATCHPOST_WAZUH_INDEXER_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("WATCHPOST_WAZUH_INDEXER_CA_FILE: no PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.WazuhIndexerInsecure {
		tlsCfg.InsecureSkipVerify = true // explicit opt-in, internal Docker network only
	}
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		Proxy:                 nil,
		MaxIdleConns:          4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &AlertsClient{
		base: u, user: cfg.WazuhIndexerUser, password: cfg.WazuhIndexerPassword,
		http: &http.Client{Transport: tr, Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// Alert is one alert for the console.
type Alert struct {
	TS          string `json:"ts"`
	Level       int    `json:"level"`
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	Type        string `json:"type"`
	DeviceID    string `json:"device_id"`
	EventID     string `json:"event_id,omitempty"`
	EventTS     string `json:"event_ts,omitempty"`
}

// AlertsAnswer is the body of GET /alerts.
type AlertsAnswer struct {
	Wazuh  bool    `json:"wazuh"`
	Alerts []Alert `json:"alerts"`
	Reason string  `json:"reason,omitempty"`
}

type searchHit struct {
	Source struct {
		Timestamp string `json:"timestamp"`
		Rule      struct {
			Level       int    `json:"level"`
			ID          string `json:"id"`
			Description string `json:"description"`
		} `json:"rule"`
		Data struct {
			Watchpost struct {
				Type     string `json:"type"`
				DeviceID string `json:"device_id"`
				ID       string `json:"id"`
				TS       string `json:"ts"`
			} `json:"watchpost"`
		} `json:"data"`
	} `json:"_source"`
}

type searchResult struct {
	Hits struct {
		Hits []searchHit `json:"hits"`
	} `json:"hits"`
}

// Search returns Watchpost alerts (documents of wazuh-alerts-* with data.watchpost.type)
// in [from, to] with rule.level >= levelMin, newest first.
func (c *AlertsClient) Search(ctx context.Context, log *slog.Logger, fromMS, toMS int64, levelMin, limit int) AlertsAnswer {
	if c.base == nil {
		return AlertsAnswer{Wazuh: false, Alerts: []Alert{}, Reason: "not_configured"}
	}
	q := map[string]any{
		"size":             limit,
		"track_total_hits": false,
		"sort":             []any{map[string]any{"timestamp": map[string]any{"order": "desc"}}},
		"_source":          []string{"timestamp", "rule.level", "rule.id", "rule.description", "data.watchpost.type", "data.watchpost.device_id", "data.watchpost.id", "data.watchpost.ts"},
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"exists": map[string]any{"field": "data.watchpost.type"}},
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": fromMS, "lte": toMS, "format": "epoch_millis"}}},
			map[string]any{"range": map[string]any{"rule.level": map[string]any{"gte": levelMin}}},
		}}},
	}
	body, _ := json.Marshal(q)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/wazuh-alerts-*/_search"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return AlertsAnswer{Alerts: []Alert{}, Reason: "unreachable"}
	}
	req.Header.Set("Content-Type", "application/json")
	if c.user != "" {
		req.SetBasicAuth(c.user, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		log.Warn("Wazuh indexer unreachable", "err", err)
		return AlertsAnswer{Alerts: []Alert{}, Reason: "unreachable"}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Warn("Wazuh indexer: unexpected response", "status", resp.StatusCode)
		return AlertsAnswer{Alerts: []Alert{}, Reason: "unreachable"}
	}
	var res searchResult
	if err := json.Unmarshal(raw, &res); err != nil {
		log.Warn("Wazuh indexer: unreadable response", "err", err)
		return AlertsAnswer{Alerts: []Alert{}, Reason: "unreachable"}
	}
	ans := AlertsAnswer{Wazuh: true, Alerts: make([]Alert, 0, len(res.Hits.Hits))}
	for _, h := range res.Hits.Hits {
		src := h.Source
		ans.Alerts = append(ans.Alerts, Alert{
			TS: normalizeWazuhTS(src.Timestamp), Level: src.Rule.Level, RuleID: src.Rule.ID, Description: src.Rule.Description,
			Type: src.Data.Watchpost.Type, DeviceID: src.Data.Watchpost.DeviceID, EventID: src.Data.Watchpost.ID, EventTS: src.Data.Watchpost.TS,
		})
	}
	return ans
}

// normalizeWazuhTS converts "2026-11-15T21:45:00.412+0000" to RFC 3339.
func normalizeWazuhTS(s string) string {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05-0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
		}
	}
	return s
}
