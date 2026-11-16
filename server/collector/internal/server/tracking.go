package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/adguard"
	"github.com/erwsim/android-telemetry/server/collector/internal/command"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
	"github.com/erwsim/android-telemetry/server/collector/internal/tracking"
)

// Tracking view (contract §9): the AdGuard Home query log is read incrementally and aggregated per hour
// and domain; the view crosses it with net.dns (applications per domain) and net.usage (bytes per
// application), all from hourly aggregates. AdGuard being down only turns "adguard" to false.

const (
	agPageSize       = 500
	agPagesPerPoll   = 40             // 20 000 entries per poll at most; the rest is read at the next ones
	agLag            = time.Minute    // an entry is counted once it is this old (the newest ones are left to the next poll)
	agInitialHistory = 24 * time.Hour // history read at the very first poll
	agMaxGaps        = 16             // unread ranges kept (after a long outage or the first poll)
	agStateKey       = "adguard_querylog"
	agWriteTimeout   = 2 * time.Minute // level change: AdGuard downloads the lists it adds
)

type trackingService struct {
	s          *Server
	client     *adguard.Client
	levels     *tracking.Levels
	classifier *tracking.Classifier
	essentials *tracking.Essentials
	poll       time.Duration

	mu        sync.Mutex
	lastOK    time.Time
	lastErr   string
	names     map[int64]string // filter list id -> name
	filters   []tracking.FilterState
	overrides map[string]string
	overErr   error // managed block unreadable

	writeMu sync.Mutex // serializes read-modify-write changes made in AdGuard Home
	pollMu  sync.Mutex // one query log reading at a time
}

func newTrackingService(s *Server) (*trackingService, error) {
	cfg := s.cfg
	own := map[string]string{}
	if u, err := url.Parse(cfg.PublicIngestURL); err == nil && u.Hostname() != "" {
		own[u.Hostname()] = "envoi des événements et commandes Vigie (serveur d'ingestion)"
	}
	if cfg.PrivateDNSHost != "" {
		own[cfg.PrivateDNSHost] = "DNS privé du téléphone (serveur Vigie) : plus aucune résolution de noms"
	}
	t := &trackingService{s: s, classifier: tracking.Default(), essentials: tracking.NewEssentials(own), poll: cfg.AdGuardPoll}
	if cfg.AdGuardLevelsFile != "" {
		l, err := tracking.LoadLevels(cfg.AdGuardLevelsFile)
		if err != nil {
			return nil, fmt.Errorf("VIGIE_ADGUARD_LEVELS_FILE : %w", err)
		}
		t.levels = l
	}
	if cfg.AdGuardURL != "" {
		c, err := adguard.New(cfg.AdGuardURL, cfg.AdGuardUser, cfg.AdGuardPassword)
		if err != nil {
			return nil, fmt.Errorf("VIGIE_ADGUARD_URL : %w", err)
		}
		t.client = c
	}
	return t, nil
}

// StartTracking starts reading the AdGuard Home query log (when configured) until ctx is canceled.
func (s *Server) StartTracking(ctx context.Context) {
	if s.tracking.client == nil {
		s.log.Info("vue pistage : AdGuard Home non configuré (VIGIE_ADGUARD_URL), vue construite depuis net.dns seul")
		return
	}
	go s.tracking.run(ctx)
}

// available reports whether AdGuard Home answered recently.
func (t *trackingService) available() bool {
	if t.client == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.lastOK.IsZero() && t.s.now().Sub(t.lastOK) < max(3*t.poll, 3*time.Minute)
}

func (t *trackingService) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := t.pollOnce(ctx); err != nil && ctx.Err() == nil {
			t.mu.Lock()
			first := t.lastErr == ""
			t.lastErr = err.Error()
			t.mu.Unlock()
			if first {
				t.s.log.Warn("vue pistage : AdGuard Home injoignable ou en erreur (nouvel essai à chaque relevé)", "err", err)
			} else {
				t.s.log.Debug("vue pistage : AdGuard Home toujours en erreur", "err", err)
			}
		}
		timer.Reset(t.poll)
	}
}

func (t *trackingService) pollOnce(ctx context.Context) error {
	t.pollMu.Lock()
	defer t.pollMu.Unlock()
	if err := t.refreshStatus(ctx); err != nil {
		return err
	}
	if err := t.readLog(ctx, agPagesPerPoll); err != nil {
		return err
	}
	t.mu.Lock()
	if t.lastErr != "" {
		t.s.log.Info("vue pistage : AdGuard Home de nouveau joignable")
	}
	t.lastErr = ""
	t.mu.Unlock()
	return nil
}

// refreshStatus reads the filter lists and the managed overrides.
func (t *trackingService) refreshStatus(ctx context.Context) error {
	st, err := t.client.FilteringStatus(ctx)
	if err != nil {
		return err
	}
	t.setStatus(st)
	return nil
}

func (t *trackingService) setStatus(st *adguard.FilterStatus) {
	names := map[int64]string{}
	var filters []tracking.FilterState
	for _, f := range st.Filters {
		names[f.ID] = f.Name
		filters = append(filters, tracking.FilterState{URL: f.URL, Name: f.Name, Enabled: f.Enabled})
	}
	for _, f := range st.WhitelistFilters {
		names[f.ID] = f.Name
		filters = append(filters, tracking.FilterState{URL: f.URL, Name: f.Name, Enabled: f.Enabled, Allowlist: true})
	}
	ov, oerr := tracking.ParseOverrides(st.UserRules)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastOK = t.s.now()
	t.names, t.filters, t.overrides, t.overErr = names, filters, ov, oerr
}

// logGap is a range of the query log still to read: the entries older than the record at Hi, down to Lo.
type logGap struct {
	// Hi is the exact time of the oldest record already read above the gap. It is the cursor given to
	// AdGuard Home (older_than), which only finds the time of an existing record (see readLog).
	Hi string `json:"hi"`
	// Lo: the entries at or before this time are counted already (or belong to an older gap).
	Lo string `json:"lo"`
	// Up: the entries after this time belong to a later reading (the "top" when the gap was opened).
	Up string `json:"up,omitempty"`
	// Alt are the times of the records read just before Hi (newer ones, nearest first): cursors to
	// fall back on when AdGuard Home does not find the record at Hi.
	Alt []string `json:"alt,omitempty"`
	// Tried counts the cursors (Hi, then Alt in order) that already brought nothing new.
	Tried int `json:"tried,omitempty"`
}

type logState struct {
	Top  string   `json:"top"`            // entries up to this time have been read (or are in a gap)
	Gaps []logGap `json:"gaps,omitempty"` // ranges below top still to read, newest first
}

func fmtNano(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (t *trackingService) loadState(ctx context.Context) (logState, error) {
	var st logState
	v, ok, err := t.s.st.GetKV(ctx, agStateKey)
	if err != nil {
		return st, err
	}
	if ok && json.Unmarshal([]byte(v), &st) == nil && st.Top != "" {
		if _, err := time.Parse(time.RFC3339Nano, st.Top); err == nil {
			return st, nil
		}
	}
	return logState{Top: fmtNano(t.s.now().Add(-agInitialHistory))}, nil
}

// readLog counts the query log entries not counted yet. Each entry is counted exactly once: an entry is
// counted by the poll whose window (previous top, now - agLag] holds its time, and each page is committed
// in one transaction with the position reached, so that a restart resumes without loss or double count.
//
// How the log is read matters. AdGuard Home (checked in the sources of v0.107.80, internal/querylog, and
// against a real instance) answers "older_than=T" by looking in its log files for a record whose time is
// EXACTLY T; when T falls between two records it returns nothing from the files, and when T is later than
// the newest record it silently skips that record. A reading that asked for "older than now - 60 s" lost
// entries at every poll. So the newest page is requested without older_than, the following ones with the
// exact time of the oldest record of the previous page (the "oldest" AdGuard Home returned), and the time
// window is applied here. When a cursor gets a short answer before the lower limit is reached, the log
// may really end there, or the cursor's record may be missing from the files (it was only in memory, or
// rotated away): the times of the records read just before it are tried as cursors before concluding.
//
// A cursor is the oldest record of a full page, 500 records deep: it is in AdGuard Home's files as long as
// querylog.size_memory stays below the page size (with a larger memory buffer the cursor can be a record
// still in memory, which is "later than the newest record" of the files: one record skipped).
//
// What the page budget leaves unread is kept as a gap and read by the next polls (agMaxGaps at most).
func (t *trackingService) readLog(ctx context.Context, budget int) error {
	state, err := t.loadState(ctx)
	if err != nil {
		return err
	}
	cutoff := t.s.now().Add(-agLag)
	top, _ := time.Parse(time.RFC3339Nano, state.Top)
	if cutoff.After(top) {
		oldTop, oldGaps := state.Top, state.Gaps
		newTop := fmtNano(cutoff)
		err := t.walk(ctx, logGap{Lo: oldTop, Up: newTop}, &budget, func(g logGap, done bool) logState {
			gaps := oldGaps
			if !done {
				gaps = append([]logGap{g}, oldGaps...)
				if len(gaps) > agMaxGaps {
					t.s.log.Warn("vue pistage : trop de plages non lues, la plus ancienne est abandonnée", "from", gaps[len(gaps)-1].Lo, "to", gaps[len(gaps)-1].Hi)
					gaps = gaps[:agMaxGaps]
				}
			}
			state = logState{Top: newTop, Gaps: gaps}
			return state
		})
		if err != nil {
			return err
		}
	}
	for len(state.Gaps) > 0 && budget > 0 {
		before := state.Gaps[0]
		rest := append([]logGap{}, state.Gaps[1:]...)
		err := t.walk(ctx, before, &budget, func(g logGap, done bool) logState {
			if done {
				state = logState{Top: state.Top, Gaps: rest}
			} else {
				state = logState{Top: state.Top, Gaps: append([]logGap{g}, rest...)}
			}
			return state
		})
		if err != nil {
			return err
		}
	}
	return nil
}

const agAltCursors = 3 // records read just before the cursor, kept as fallback cursors

// walk reads one range of the log, newest first, within the page budget: the entries older than the
// record at g.Hi (from the newest entry when g.Hi is empty) whose time is in (g.Lo, g.Up]. Each page is
// committed with the state built by next(what remains of the range, range finished).
func (t *trackingService) walk(ctx context.Context, g logGap, budget *int, next func(g logGap, done bool) logState) error {
	lo, err := time.Parse(time.RFC3339Nano, g.Lo)
	if err != nil {
		return t.s.st.ApplyTrackingPage(ctx, nil, agStateKey, stateJSON(next(g, true))) // unreadable range: dropped
	}
	var up, bound time.Time // zero: no limit
	if g.Up != "" {
		up, _ = time.Parse(time.RFC3339Nano, g.Up)
	}
	// recent holds the times of the last distinct records read, newest first; its last element is the
	// cursor (the oldest record read), the ones before it are the fallback cursors.
	var recent []string
	if g.Hi != "" {
		if bound, err = time.Parse(time.RFC3339Nano, g.Hi); err != nil {
			return t.s.st.ApplyTrackingPage(ctx, nil, agStateKey, stateJSON(next(g, true)))
		}
		for i := len(g.Alt) - 1; i >= 0; i-- {
			recent = append(recent, g.Alt[i])
		}
		recent = append(recent, g.Hi)
	}
	tries := min(max(g.Tried, 0), max(len(recent)-1, 0)) // cursors tried in a row that brought nothing new
	remaining := func() logGap {
		r := logGap{Lo: g.Lo, Up: g.Up, Tried: tries}
		if n := len(recent); n > 0 {
			r.Hi = recent[n-1]
			for i := n - 2; i >= 0; i-- {
				r.Alt = append(r.Alt, recent[i])
			}
		}
		return r
	}
	for *budget > 0 {
		cursor := ""
		if n := len(recent); n > 0 {
			cursor = recent[n-1-tries]
		}
		page, err := t.client.QueryLog(ctx, cursor, agPageSize)
		if err != nil {
			return err
		}
		*budget--
		res := t.aggregate(page.Data, lo, up, bound)
		short := len(page.Data) < agPageSize // "oldest" is not used: the cursor is taken from the entries themselves
		if len(res.times) > 0 {
			// New records below the previous cursor: they become the cursor and its fallbacks.
			recent = append(recent, res.times...)
			if len(recent) > agAltCursors+1 {
				recent = recent[len(recent)-agAltCursors-1:]
			}
			bound = res.oldest
			tries = 0
		} else if cursor != "" {
			tries++
		}
		// The range is finished when the lower limit is reached, when the newest page (asked without a
		// cursor) is not full — it is the whole log —, or when the cursor and then each of its fallbacks
		// brought nothing new. A short answer that brought something is not yet the end: the next turn
		// asks again from its oldest record.
		done := res.reached
		if cursor == "" {
			done = done || short || len(res.times) == 0
		} else if len(res.times) == 0 && tries >= len(recent) {
			done = true
			t.s.log.Debug("vue pistage : fin du journal d'AdGuard Home atteinte avant la limite basse de la plage", "cursor", recent[len(recent)-1], "lo", g.Lo)
		}
		if err := t.s.st.ApplyTrackingPage(ctx, res.rows, agStateKey, stateJSON(next(remaining(), done))); err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func stateJSON(st logState) string {
	b, _ := json.Marshal(st)
	return string(b)
}

type trackKey struct {
	hour           int64
	client, domain string
}

type pageResult struct {
	rows    []store.TrackingRow
	reached bool      // an entry at or before the lower limit was seen
	oldest  time.Time // time of the oldest new record of the page
	times   []string  // times of the new records, newest first, as AdGuard Home wrote them (distinct)
}

// aggregate turns the entries of a page into hourly rows. Only the records older than bound (those not
// read yet in this walk; zero: all) are considered, and among them the entries whose time is in (lo, up]
// are counted (up zero: no upper limit).
func (t *trackingService) aggregate(items []adguard.QueryLogItem, lo, up, bound time.Time) pageResult {
	t.mu.Lock()
	names := t.names
	t.mu.Unlock()
	acc := map[trackKey]*store.TrackingRow{}
	var order []trackKey
	var res pageResult
	type seen struct {
		ts  time.Time
		raw string
	}
	var fresh []seen
	for i := range items {
		it := &items[i]
		ts, err := time.Parse(time.RFC3339Nano, it.Time)
		if err != nil {
			continue
		}
		if !bound.IsZero() && !ts.Before(bound) {
			continue // already read in this walk (answer to a fallback cursor)
		}
		fresh = append(fresh, seen{ts, it.Time})
		if !ts.After(lo) {
			res.reached = true
			continue
		}
		if !up.IsZero() && ts.After(up) {
			continue // too recent: counted by a later poll
		}
		d := tracking.Normalize(it.Question.Name)
		if d == "" || len(d) > 253 || strings.ContainsAny(d, " \t\r\n") {
			continue
		}
		client := it.ClientID
		if client == "" {
			client = it.Client
		}
		if len(client) > 64 {
			client = client[:64]
		}
		ms := ts.UnixMilli()
		k := trackKey{hour: ms - ms%3600000, client: client, domain: d}
		r := acc[k]
		if r == nil {
			r = &store.TrackingRow{HourMS: k.hour, Client: client, Domain: d}
			acc[k] = r
			order = append(order, k)
		}
		r.Queries++
		blocked, reason := classifyReason(it, names)
		if blocked {
			r.Blocked++
		}
		if reason != "" && r.Reason == "" { // newest first: keep the most recent reason
			r.Reason = reason
		}
	}
	// AdGuard Home sorts its answer, newest first; do not depend on it for the cursor.
	sort.SliceStable(fresh, func(i, j int) bool { return fresh[i].ts.After(fresh[j].ts) })
	for i, f := range fresh {
		if i == 0 || !f.ts.Equal(fresh[i-1].ts) {
			res.times = append(res.times, f.raw)
		}
		res.oldest = f.ts
	}
	res.rows = make([]store.TrackingRow, 0, len(order))
	for _, k := range order {
		res.rows = append(res.rows, *acc[k])
	}
	return res
}

// classifyReason tells whether an entry was blocked and gives a readable reason: the filter list name or
// the rule, the blocked service, etc.
func classifyReason(it *adguard.QueryLogItem, names map[int64]string) (bool, string) {
	listID, text := int64(-1), it.Rule
	if len(it.Rules) > 0 {
		listID, text = it.Rules[0].FilterListID, it.Rules[0].Text
	} else if it.FilterID != nil {
		listID = *it.FilterID
	}
	text = clipText(text, 160)
	ruleReason := func(allow bool) string {
		if listID == 0 {
			if ov, err := tracking.ParseOverrides([]string{tracking.BlockBegin, text, tracking.BlockEnd}); err == nil && len(ov) == 1 {
				if allow {
					return "Autorisation manuelle (Vigie)"
				}
				return "Blocage manuel (Vigie)"
			}
			if text != "" {
				return "Règle personnalisée : " + text
			}
			return "Règle personnalisée"
		}
		name := names[listID]
		if name == "" {
			name = "n° " + strconv.FormatInt(listID, 10)
		}
		if allow {
			return "Liste d'autorisation : " + clipText(name, 120)
		}
		return "Liste : " + clipText(name, 120)
	}
	switch it.Reason {
	case "FilteredBlackList":
		return true, ruleReason(false)
	case "NotFilteredWhiteList":
		return false, ruleReason(true)
	case "FilteredBlockedService":
		return true, "Service bloqué : " + clipText(it.ServiceName, 80)
	case "FilteredSafeBrowsing":
		return true, "Navigation sécurisée (site dangereux)"
	case "FilteredParental":
		return true, "Contrôle parental"
	case "FilteredInvalid":
		return true, "Requête invalide"
	case "FilteredSafeSearch":
		return false, "Recherche sécurisée"
	case "Rewrite", "RewriteEtcHosts", "RewriteRule":
		return false, "Réécriture DNS"
	}
	return false, ""
}

func clipText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n] + "…"
}

// --- console API ---------------------------------------------------------------------------------

type trackingQuery struct {
	device   string
	from, to int64
}

func (s *Server) trackingParams(v url.Values) (trackingQuery, error) {
	var q trackingQuery
	var err error
	if q.device, err = deviceParam(v, false); err != nil {
		return q, err
	}
	q.from, q.to, err = timeRange(v, true, s.now(), 0)
	return q, err
}

// input gathers the aggregates of the period.
func (s *Server) trackingInput(ctx context.Context, q trackingQuery, labels bool) (*tracking.Input, error) {
	t := s.tracking
	in := &tracking.Input{AdGuard: t.client != nil, Classifier: t.classifier, Overrides: map[string]string{}}
	var err error
	if in.AdGuard {
		var clients []string
		if q.device != "" {
			clients = s.cfg.AdGuardClients[q.device]
		}
		if in.AdGuardCounts, err = s.st.TrackingCounts(ctx, clients, q.from, q.to); err != nil {
			return nil, err
		}
		t.mu.Lock()
		for d, a := range t.overrides {
			in.Overrides[d] = a
		}
		t.mu.Unlock()
	}
	if in.DNS, err = s.st.DNSAppDomains(ctx, q.device, q.from, q.to); err != nil {
		return nil, err
	}
	if in.Usage, err = s.st.UsageBytes(ctx, q.device, q.from, q.to); err != nil {
		return nil, err
	}
	if labels {
		if in.Labels, err = s.st.AppLabels(ctx, q.device); err != nil {
			return nil, err
		}
	}
	return in, nil
}

func (t *trackingService) currentLevel() string {
	if !t.available() || t.levels == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.levels.Current(t.filters)
}

func (s *Server) handleTrackingSummary(w http.ResponseWriter, r *http.Request) {
	q, err := s.trackingParams(r.URL.Query())
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	in, err := s.trackingInput(ctx, q, false)
	if err != nil {
		s.fail(w, err)
		return
	}
	domains := tracking.Domains(in)
	totals, pubs := tracking.Summary(in, domains)
	resp := map[string]any{
		"adguard": s.tracking.available(), "levels": s.tracking.levels.Infos(), "totals": totals, "publishers": pubs,
	}
	if lv := s.tracking.currentLevel(); lv != "" {
		resp["level"] = lv
	}
	writeJSON(w, http.StatusOK, resp)
}

func encodeDomainCursor(queries int64, domain string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(queries, 10) + "|" + domain))
}

func decodeDomainCursor(c string) (int64, string, bool) {
	if len(c) > 400 {
		return 0, "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, "", false
	}
	a, d, ok := strings.Cut(string(b), "|")
	n, err := strconv.ParseInt(a, 10, 64)
	return n, d, ok && err == nil
}

func (s *Server) publisherParam(v url.Values) (string, error) {
	p := v.Get("publisher")
	if p != "" && !s.tracking.classifier.Valid(p) {
		return "", paramErr("invalid_parameter", "publisher inconnu")
	}
	return p, nil
}

func (s *Server) handleTrackingDomains(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	q, err := s.trackingParams(v)
	if err != nil {
		s.fail(w, err)
		return
	}
	pub, err := s.publisherParam(v)
	if err != nil {
		s.fail(w, err)
		return
	}
	status := v.Get("status")
	if status != "" && status != "all" && status != tracking.StatusBlocked && status != tracking.StatusAllowed {
		s.fail(w, paramErr("invalid_parameter", "status : blocked, allowed ou all"))
		return
	}
	limit, err := intParam(v, "limit", 50, 1, 200)
	if err != nil {
		s.fail(w, err)
		return
	}
	search := strings.ToLower(strings.TrimSpace(v.Get("q")))
	if len(search) > 100 {
		s.fail(w, paramErr("invalid_parameter", "paramètre q : 100 octets au plus"))
		return
	}
	var hasCursor bool
	var cq int64
	var cd string
	if c := v.Get("cursor"); c != "" {
		if cq, cd, hasCursor = decodeDomainCursor(c); !hasCursor {
			s.fail(w, paramErr("invalid_parameter", "curseur invalide"))
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	in, err := s.trackingInput(ctx, q, false)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := []*tracking.Domain{}
	more := false
	for _, d := range tracking.Domains(in) {
		if hasCursor && !tracking.Before(cq, cd, d.Queries, d.Domain) {
			continue
		}
		if pub != "" && d.Publisher != pub {
			continue
		}
		switch status {
		case tracking.StatusBlocked:
			if d.Blocked == 0 {
				continue
			}
		case tracking.StatusAllowed:
			if d.Status != tracking.StatusAllowed && d.Status != tracking.StatusMixed {
				continue
			}
		}
		if search != "" && !strings.Contains(d.Domain, search) {
			continue
		}
		if len(out) == limit {
			more = true
			break
		}
		out = append(out, d)
	}
	resp := map[string]any{"adguard": s.tracking.available(), "domains": out}
	if more {
		last := out[len(out)-1]
		resp["next_cursor"] = encodeDomainCursor(last.Queries, last.Domain)
	}
	writeJSON(w, http.StatusOK, resp)
}

const maxTrackingApps = 500

func (s *Server) handleTrackingApps(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	q, err := s.trackingParams(v)
	if err != nil {
		s.fail(w, err)
		return
	}
	pub, err := s.publisherParam(v)
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	in, err := s.trackingInput(ctx, q, true)
	if err != nil {
		s.fail(w, err)
		return
	}
	apps := tracking.Apps(in, tracking.Domains(in), pub)
	if len(apps) > maxTrackingApps {
		apps = apps[:maxTrackingApps]
	}
	writeJSON(w, http.StatusOK, map[string]any{"adguard": s.tracking.available(), "apps": apps})
}

// readStrictBody reads a small JSON object with only the allowed keys.
func readStrictBody(w http.ResponseWriter, r *http.Request, allowed ...string) (map[string]json.RawMessage, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "requête trop volumineuse")
		return nil, false
	}
	fields, err := command.StrictObject(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "objet JSON attendu : "+err.Error())
		return nil, false
	}
	for k := range fields {
		ok := false
		for _, a := range allowed {
			ok = ok || a == k
		}
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_json", "champ inconnu : "+k)
			return nil, false
		}
	}
	return fields, true
}

func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func (s *Server) adguardUnavailable(w http.ResponseWriter) bool {
	if !s.tracking.available() {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, "adguard_unavailable", "AdGuard Home non configuré ou injoignable")
		return true
	}
	return false
}

func (s *Server) adguardFailed(w http.ResponseWriter, what string, err error) {
	s.log.Error("vue pistage : "+what+" impossible dans AdGuard Home", "err", err)
	writeError(w, http.StatusBadGateway, "adguard_error", "AdGuard Home a refusé ou n'a pas répondu ("+what+")")
}

func (s *Server) handleTrackingOverride(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userKey).(string)
	fields, ok := readStrictBody(w, r, "domain", "action", "force")
	if !ok {
		return
	}
	domain, ok1 := jsonString(fields["domain"])
	action, ok2 := jsonString(fields["action"])
	force := false
	if raw, present := fields["force"]; present {
		switch string(raw) {
		case "true":
			force = true
		case "false", "null":
		default:
			writeError(w, http.StatusBadRequest, "invalid_json", "force : booléen attendu")
			return
		}
	}
	domain = tracking.Normalize(domain)
	if !ok1 || !tracking.ValidDomain(domain) {
		writeError(w, http.StatusBadRequest, "invalid_domain", "nom de domaine invalide (lettres, chiffres, tirets, points ; forme xn-- pour les noms internationaux)")
		return
	}
	if !ok2 || (action != tracking.ActionBlock && action != tracking.ActionAllow && action != tracking.ActionDefault) {
		writeError(w, http.StatusBadRequest, "invalid_action", "action : block, allow ou default")
		return
	}
	if action == tracking.ActionBlock && !force {
		if broken := s.tracking.essentials.BrokenBy(domain); len(broken) > 0 {
			parts := make([]string, 0, len(broken))
			for _, b := range broken {
				parts = append(parts, b.Domain+" ("+b.Breaks+")")
			}
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   "essential_domain",
				"message": "bloquer " + domain + " casserait : " + strings.Join(parts, " ; ") + ". Confirmez avec \"force\": true.",
				"breaks":  broken,
			})
			return
		}
	}
	if s.adguardUnavailable(w) {
		return
	}
	t := s.tracking
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), agWriteTimeout)
	defer cancel()
	st, err := t.client.FilteringStatus(ctx)
	if err != nil {
		s.adguardFailed(w, "lecture des règles", err)
		return
	}
	previous := ""
	if ov, perr := tracking.ParseOverrides(st.UserRules); perr == nil {
		previous = ov[domain]
	}
	rules, changed, err := tracking.ApplyOverride(st.UserRules, domain, action)
	if errors.Is(err, tracking.ErrCorruptBlock) {
		writeError(w, http.StatusConflict, "corrupt_rules", err.Error()+" : corrigez-le dans AdGuard Home")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_domain", err.Error())
		return
	}
	if changed {
		if err := t.client.SetRules(ctx, rules); err != nil {
			s.adguardFailed(w, "écriture des règles", err)
			return
		}
		st.UserRules = rules
		// Allowing a domain weakens the blocking; forcing the blocking of an essential domain can cut the
		// phone off (push, updates, Vigie itself): both are what someone holding the console session
		// would do, and are worth an alert.
		sev := 1
		if action == tracking.ActionAllow || (action == tracking.ActionDefault && previous == tracking.ActionBlock) ||
			(action == tracking.ActionBlock && len(t.essentials.BrokenBy(domain)) > 0) {
			sev = 2
		}
		data := map[string]any{"domain": domain, "action": action, "forced": force, "user": user}
		if previous != "" {
			data["previous"] = previous
		}
		s.trackingEvent(ctx, "tracking.override", sev, data)
	}
	t.setStatus(st)
	s.log.Info("vue pistage : règle modifiée", "domain", domain, "action", action, "force", force, "changed", changed, "user", user)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// levelRank orders the blocking levels from the weakest to the strongest (-1: unknown).
func levelRank(key string) int {
	for i, k := range tracking.LevelKeys {
		if k == key {
			return i
		}
	}
	return -1
}

// trackingEvent records a change made in AdGuard Home from the console as events produced by the collector
// (source "server", one per device), exported to Wazuh like the command events: weakening the blocking is
// what someone who got hold of the console session would do. The change itself is already applied: a
// failure here is logged, not returned.
func (s *Server) trackingEvent(ctx context.Context, typ string, sev int, data map[string]any) {
	evs, err := s.st.AddServerEvents(ctx, typ, sev, data, s.now())
	if err != nil {
		s.log.Error("vue pistage : événement non enregistré", "type", typ, "err", err)
		return
	}
	s.published(evs)
}

func (s *Server) handleTrackingLevelGet(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"adguard": s.tracking.available(), "levels": s.tracking.levels.Infos()}
	if lv := s.tracking.currentLevel(); lv != "" {
		resp["level"] = lv
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTrackingLevelPut(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userKey).(string)
	fields, ok := readStrictBody(w, r, "level")
	if !ok {
		return
	}
	level, ok := jsonString(fields["level"])
	t := s.tracking
	if t.levels == nil {
		writeError(w, http.StatusServiceUnavailable, "levels_not_configured", "correspondance niveaux → listes absente (VIGIE_ADGUARD_LEVELS_FILE)")
		return
	}
	if !ok || !t.levels.Has(level) {
		writeError(w, http.StatusBadRequest, "invalid_level", "level : "+strings.Join(tracking.LevelKeys, ", "))
		return
	}
	if s.adguardUnavailable(w) {
		return
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), agWriteTimeout)
	defer cancel()
	st, err := t.client.FilteringStatus(ctx)
	if err != nil {
		s.adguardFailed(w, "lecture des listes", err)
		return
	}
	t.setStatus(st)
	t.mu.Lock()
	filters := append([]tracking.FilterState(nil), t.filters...)
	t.mu.Unlock()
	plan, err := t.levels.Plan(level, filters)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_level", err.Error())
		return
	}
	oldLevel := t.levels.Current(filters)
	for _, a := range plan {
		var err error
		if a.Add {
			err = t.client.AddFilter(ctx, a.URL, a.Name, a.Allowlist)
		} else {
			err = t.client.SetFilterEnabled(ctx, a.URL, a.Name, a.Allowlist, a.Enabled)
		}
		if err != nil {
			if st, rerr := t.client.FilteringStatus(ctx); rerr == nil {
				t.setStatus(st)
			}
			s.adguardFailed(w, "changement de liste ("+a.Name+")", err)
			return
		}
	}
	if st, err := t.client.FilteringStatus(ctx); err == nil {
		t.setStatus(st)
	}
	if len(plan) > 0 {
		data := map[string]any{"new": level, "changes": len(plan), "user": user}
		if oldLevel != "" { // absent when the lists had been changed by hand and matched no level
			data["old"] = oldLevel
		}
		sev := 1
		if levelRank(level) < levelRank(oldLevel) || oldLevel == "" {
			sev = 2 // blocking weakened (or from an unknown state)
		}
		s.trackingEvent(ctx, "tracking.level_changed", sev, data)
	}
	s.log.Info("vue pistage : niveau de blocage changé", "level", level, "old", oldLevel, "changes", len(plan), "user", user)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
