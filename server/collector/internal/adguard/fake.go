package adguard

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fake is a small in-memory AdGuard Home serving the routes Vigie uses (query log, filtering status,
// user rules, filter lists), for the tests and the local demonstration (sim --fake-adguard). Queries
// are decided like AdGuard Home does with its rules: enabled lists block their domains and subdomains,
// "@@" rules allow, "$important" wins.
type Fake struct {
	User, Password string

	mu        sync.Mutex
	log       []fakeEntry // sorted by time, oldest first
	filters   []fakeFilter
	userRules []string
	nextID    int64
	maxLog    int
	requests  map[string]int
}

type fakeEntry struct {
	t        time.Time
	client   string
	clientID string
	domain   string
	reason   string
	listID   int64
	rule     string
}

type fakeFilter struct {
	Filter
	allowlist bool
	domains   []string
}

// FakeLists are the filter lists known to the fake, by URL: the domains each one blocks (or allows, for
// an allowlist). Their URLs are those of the example levels file of the README.
var FakeLists = map[string]struct {
	Name    string
	Domains []string
}{
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt": {"AdGuard DNS filter", []string{
		"app-measurement.com", "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
		"googletagmanager.com", "scorecardresearch.com", "criteo.com", "appsflyer.com", "adjust.com", "samsungads.com",
		"firebaselogging-pa.googleapis.com", "tiqcdn.com", "privacy-mgmt.com"}},
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt": {"AdAway Default Blocklist", []string{
		"doubleclick.net", "scorecardresearch.com", "googleadservices.com"}},
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt": {"HaGeZi - Native Tracker Samsung", []string{
		"dqa.samsungdm.com", "dc.samsungdm.com", "samsungads.com", "gos-api.gos-gsp.io", "samsungqbe.com"}},
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.tiktok.txt": {"HaGeZi - Native Tracker TikTok", []string{
		"tiktokv.com", "byteoversea.com", "ibytedtos.com"}},
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winoffice.txt": {"HaGeZi - Native Tracker Microsoft", []string{
		"vortex.data.microsoft.com", "settings-win.data.microsoft.com"}},
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt": {"HaGeZi - Multi PRO++", []string{
		"app-measurement.com", "doubleclick.net", "play-services-telemetry.googleapis.com", "firebaselogging-pa.googleapis.com",
		"clientservices.googleapis.com", "incoming.telemetry.mozilla.org", "api.segment.io", "graph.instagram.com",
		"sb.scorecardresearch.com", "dqa.samsungdm.com", "dc.samsungdm.com", "cdn.privacy-mgmt.com"}},
}

// NewFake returns a fake with AdGuard Home's two default lists enabled and one rule entered by hand.
func NewFake(user, password string) *Fake {
	f := &Fake{User: user, Password: password, maxLog: 500000, requests: map[string]int{},
		userRules: []string{"! règle saisie à la main dans AdGuard Home", "||tracker.example^"}}
	f.addFilter("https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "AdGuard DNS filter", false, true)
	f.addFilter("https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt", "AdAway Default Blocklist", false, false)
	return f
}

func (f *Fake) addFilter(url, name string, allowlist, enabled bool) {
	f.nextID++
	ff := fakeFilter{Filter: Filter{ID: f.nextID, Name: name, URL: url, Enabled: enabled}, allowlist: allowlist}
	if l, ok := FakeLists[url]; ok {
		ff.domains = l.Domains
	}
	f.filters = append(f.filters, ff)
}

// Requests returns how many times a path was called.
func (f *Fake) Requests(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[path]
}

// UserRules returns a copy of the user rules.
func (f *Fake) UserRules() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.userRules...)
}

// EnabledLists returns the URLs of the enabled lists.
func (f *Fake) EnabledLists() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, ff := range f.filters {
		if ff.Enabled {
			out = append(out, ff.URL)
		}
	}
	sort.Strings(out)
	return out
}

func matches(domain, suffix string) bool {
	return domain == suffix || strings.HasSuffix(domain, "."+suffix)
}

var fakeRuleRe = regexp.MustCompile(`^(@@)?\|\|([^\^]+)\^(\$important)?$`)

// decide applies the rules to a domain (caller holds the lock).
func (f *Fake) decide(domain string) (reason string, listID int64, rule string) {
	type hit struct {
		allow, important bool
		listID           int64
		text             string
	}
	var hits []hit
	for _, r := range f.userRules {
		m := fakeRuleRe.FindStringSubmatch(strings.TrimSpace(r))
		if m != nil && matches(domain, m[2]) {
			hits = append(hits, hit{allow: m[1] == "@@", important: m[3] != "", listID: 0, text: strings.TrimSpace(r)})
		}
	}
	for _, ff := range f.filters {
		if !ff.Enabled {
			continue
		}
		for _, d := range ff.domains {
			if matches(domain, d) {
				text := "||" + d + "^"
				if ff.allowlist {
					text = "@@" + text
				}
				hits = append(hits, hit{allow: ff.allowlist, listID: ff.ID, text: text})
				break
			}
		}
	}
	best := -1
	rank := func(h hit) int {
		switch {
		case h.allow && h.important:
			return 4
		case h.important:
			return 3
		case h.allow:
			return 2
		}
		return 1
	}
	for i, h := range hits {
		if best < 0 || rank(h) > rank(hits[best]) {
			best = i
		}
	}
	if best < 0 {
		return "NotFilteredNotFound", 0, ""
	}
	h := hits[best]
	if h.allow {
		return "NotFilteredWhiteList", h.listID, h.text
	}
	return "FilteredBlackList", h.listID, h.text
}

// AddQuery records a DNS query made at t by a client (ClientID when not empty, as with DNS-over-TLS).
func (f *Fake) AddQuery(t time.Time, client, clientID, domain string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	reason, listID, rule := f.decide(domain)
	e := fakeEntry{t: t.UTC(), client: client, clientID: clientID, domain: domain, reason: reason, listID: listID, rule: rule}
	i := sort.Search(len(f.log), func(i int) bool { return f.log[i].t.After(e.t) })
	f.log = append(f.log, fakeEntry{})
	copy(f.log[i+1:], f.log[i:])
	f.log[i] = e
	if len(f.log) > f.maxLog {
		f.log = f.log[len(f.log)-f.maxLog:]
	}
}

// Len returns the number of entries of the query log.
func (f *Fake) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.log)
}

// ServeHTTP implements the routes of AdGuard Home used by Vigie.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if f.User != "" && (!ok || subtle.ConstantTimeCompare([]byte(u), []byte(f.User)) != 1 ||
		subtle.ConstantTimeCompare([]byte(p), []byte(f.Password)) != 1) {
		w.Header().Set("WWW-Authenticate", `Basic realm="AdGuard Home"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	f.requests[r.URL.Path]++
	f.mu.Unlock()
	if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /control/status":
		writeFake(w, map[string]any{"version": "v0.107.80-fake", "running": true, "protection_enabled": true})
	case "GET /control/querylog":
		f.serveQueryLog(w, r)
	case "GET /control/filtering/status":
		f.mu.Lock()
		st := FilterStatus{Enabled: true, Filters: []Filter{}, WhitelistFilters: []Filter{}, UserRules: append([]string{}, f.userRules...)}
		for _, ff := range f.filters {
			if ff.allowlist {
				st.WhitelistFilters = append(st.WhitelistFilters, ff.Filter)
			} else {
				st.Filters = append(st.Filters, ff.Filter)
			}
		}
		f.mu.Unlock()
		writeFake(w, st)
	case "POST /control/filtering/set_rules":
		var req struct {
			Rules []string `json:"rules"`
		}
		if !readFake(w, r, &req) {
			return
		}
		f.mu.Lock()
		f.userRules = req.Rules
		f.mu.Unlock()
	case "POST /control/filtering/set_url":
		var req struct {
			URL       string `json:"url"`
			Whitelist bool   `json:"whitelist"`
			Data      *struct {
				Name    string `json:"name"`
				URL     string `json:"url"`
				Enabled bool   `json:"enabled"`
			} `json:"data"`
		}
		if !readFake(w, r, &req) {
			return
		}
		if req.Data == nil {
			http.Error(w, "data is absent", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		for i := range f.filters {
			if f.filters[i].URL == req.URL && f.filters[i].allowlist == req.Whitelist {
				f.filters[i].Enabled, f.filters[i].Name = req.Data.Enabled, req.Data.Name
				return
			}
		}
		http.Error(w, "filter not found", http.StatusBadRequest)
	case "POST /control/filtering/add_url":
		var req struct {
			Name      string `json:"name"`
			URL       string `json:"url"`
			Whitelist bool   `json:"whitelist"`
		}
		if !readFake(w, r, &req) {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, ff := range f.filters {
			if ff.URL == req.URL {
				http.Error(w, "Filter with URL: filter URL already added", http.StatusBadRequest)
				return
			}
		}
		f.addFilter(req.URL, req.Name, req.Whitelist, true)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "OK 1 rules\n")
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) serveQueryLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 500
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		limit = n
	}
	var older time.Time
	if v := q.Get("older_than"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			http.Error(w, "parsing params: "+err.Error(), http.StatusBadRequest)
			return
		}
		older = t
	}
	f.mu.Lock()
	end := len(f.log)
	if !older.IsZero() {
		end = sort.Search(len(f.log), func(i int) bool { return !f.log[i].t.Before(older) })
	}
	data := []map[string]any{}
	for i := end - 1; i >= 0 && len(data) < limit; i-- {
		e := f.log[i]
		item := map[string]any{
			"time": e.t.Format(time.RFC3339Nano), "client": e.client, "client_proto": "dot", "cached": false,
			"elapsedMs": "1.25", "status": "NOERROR", "reason": e.reason, "upstream": "https://dns10.quad9.net/dns-query",
			"question":    map[string]any{"class": "IN", "name": e.domain, "type": "A"},
			"client_info": map[string]any{"disallowed": false, "disallowed_rule": "", "name": "", "whois": map[string]any{}},
			"answer":      []any{},
		}
		if e.clientID != "" {
			item["client_id"] = e.clientID
		}
		if e.rule != "" {
			item["rules"] = []map[string]any{{"filter_list_id": e.listID, "text": e.rule}}
			item["filterId"], item["rule"] = e.listID, e.rule
		} else {
			item["rules"] = []any{}
		}
		data = append(data, item)
	}
	f.mu.Unlock()
	resp := map[string]any{"data": data, "oldest": ""}
	if len(data) > 0 {
		resp["oldest"] = data[len(data)-1]["time"]
	}
	writeFake(w, resp)
}

func writeFake(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func readFake(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		http.Error(w, "decoding request: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}
