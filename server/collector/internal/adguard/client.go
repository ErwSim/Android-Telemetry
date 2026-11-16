// Package adguard is a minimal client of the AdGuard Home administration API (v0.107.x, routes checked
// against openapi/openapi.yaml of the v0.107.80 tag): query log, filtering status, user rules and filter
// lists. The base URL comes from the configuration only (never from a request), redirects are not
// followed and responses are size-bounded.
package adguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/config"
)

// Client calls the AdGuard Home API with HTTP basic authentication.
type Client struct {
	base       string
	user, pass string
	http       *http.Client
}

const (
	maxQueryLogBytes = 32 << 20
	maxStatusBytes   = 8 << 20
	requestTimeout   = 30 * time.Second
)

// New returns a client for the AdGuard Home instance at baseURL (e.g. http://adguardhome:3000).
func New(baseURL, user, pass string) (*Client, error) {
	if err := config.CheckAdGuardURL(baseURL); err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // internal service: never through an environment proxy
	return &Client{
		base: strings.TrimRight(baseURL, "/"), user: user, pass: pass,
		http: &http.Client{
			Transport: tr,
			Timeout:   requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirection refusée")
			},
		},
	}, nil
}

// StatusError is a non-2xx answer of AdGuard Home.
type StatusError struct {
	Code int
	Path string
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("AdGuard Home %s : HTTP %d %s", e.Path, e.Code, e.Body)
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body any, limit int64, out any) error {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if c.user != "" || c.pass != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// The URL holds no credential (checked at configuration), so the error can be logged.
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return &StatusError{Code: resp.StatusCode, Path: path, Body: sanitize(string(b))}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(b)) > limit {
		return fmt.Errorf("AdGuard Home %s : réponse supérieure à %d octets", path, limit)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("AdGuard Home %s : réponse illisible : %w", path, err)
	}
	return nil
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
}

// QueryLog is the answer of GET /control/querylog.
type QueryLog struct {
	Oldest string         `json:"oldest"`
	Data   []QueryLogItem `json:"data"`
}

// QueryLogItem is one entry of the query log (only the fields Watchpost uses).
type QueryLogItem struct {
	Time     string `json:"time"`
	Client   string `json:"client"`
	ClientID string `json:"client_id,omitempty"`
	Question struct {
		Name string `json:"name"`
		Type string `json:"type,omitempty"`
	} `json:"question"`
	Reason      string       `json:"reason"`
	Rules       []ResultRule `json:"rules,omitempty"`
	ServiceName string       `json:"service_name,omitempty"`
	// Deprecated fields, still sent by v0.107.x, read when "rules" is absent.
	FilterID *int64 `json:"filterId,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

// ResultRule is a rule applied to a query.
type ResultRule struct {
	FilterListID int64  `json:"filter_list_id"`
	Text         string `json:"text"`
}

// QueryLog returns up to limit entries strictly older than olderThan ("" for the newest), newest first.
func (c *Client) QueryLog(ctx context.Context, olderThan string, limit int) (*QueryLog, error) {
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if olderThan != "" {
		q.Set("older_than", olderThan)
	}
	var out QueryLog
	if err := c.do(ctx, http.MethodGet, "/control/querylog", q, nil, maxQueryLogBytes, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Filter is one filter list of GET /control/filtering/status.
type Filter struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// FilterStatus is the answer of GET /control/filtering/status.
type FilterStatus struct {
	Enabled          bool     `json:"enabled"`
	Filters          []Filter `json:"filters"`
	WhitelistFilters []Filter `json:"whitelist_filters"`
	UserRules        []string `json:"user_rules"`
}

// FilteringStatus reads the filter lists and the user rules.
func (c *Client) FilteringStatus(ctx context.Context) (*FilterStatus, error) {
	var out FilterStatus
	if err := c.do(ctx, http.MethodGet, "/control/filtering/status", nil, nil, maxStatusBytes, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetRules replaces the user rules (POST /control/filtering/set_rules).
func (c *Client) SetRules(ctx context.Context, rules []string) error {
	if rules == nil {
		rules = []string{}
	}
	return c.do(ctx, http.MethodPost, "/control/filtering/set_rules", nil, map[string]any{"rules": rules}, 0, nil)
}

// SetFilterEnabled changes the enabled state of a filter list (POST /control/filtering/set_url).
func (c *Client) SetFilterEnabled(ctx context.Context, listURL, name string, allowlist, enabled bool) error {
	return c.do(ctx, http.MethodPost, "/control/filtering/set_url", nil, map[string]any{
		"url": listURL, "whitelist": allowlist, "data": map[string]any{"name": name, "url": listURL, "enabled": enabled},
	}, 0, nil)
}

// AddFilter adds a filter list, enabled (POST /control/filtering/add_url).
func (c *Client) AddFilter(ctx context.Context, listURL, name string, allowlist bool) error {
	return c.do(ctx, http.MethodPost, "/control/filtering/add_url", nil, map[string]any{
		"name": name, "url": listURL, "whitelist": allowlist,
	}, 0, nil)
}
