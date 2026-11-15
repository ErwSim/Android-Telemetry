package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

const queryTimeout = 30 * time.Second

// badRequest is a parameter validation error.
type badRequest struct{ code, msg string }

func (e *badRequest) Error() string { return e.msg }

func paramErr(code, format string, a ...any) error {
	return &badRequest{code: code, msg: fmt.Sprintf(format, a...)}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	var br *badRequest
	switch {
	case errors.As(err, &br):
		writeError(w, http.StatusBadRequest, br.code, br.msg)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "introuvable")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusServiceUnavailable, "timeout", "requête trop longue, réduisez l'intervalle")
	case errors.Is(err, context.Canceled):
		// client went away
	default:
		s.log.Error("API console : erreur", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erreur interne")
	}
}

func parseTime(v url.Values, name string, required bool) (time.Time, bool, error) {
	raw := v.Get(name)
	if raw == "" {
		if required {
			return time.Time{}, false, paramErr("missing_parameter", "paramètre %s requis (RFC 3339)", name)
		}
		return time.Time{}, false, nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false, paramErr("invalid_parameter", "paramètre %s : date RFC 3339 attendue", name)
	}
	return t, true, nil
}

// timeRange parses from/to (inclusive). When optional and absent, defaults apply.
func timeRange(v url.Values, required bool, now time.Time, defaultSpan time.Duration) (int64, int64, error) {
	from, hasFrom, err := parseTime(v, "from", required)
	if err != nil {
		return 0, 0, err
	}
	to, hasTo, err := parseTime(v, "to", required)
	if err != nil {
		return 0, 0, err
	}
	if !hasTo {
		to = now
	}
	if !hasFrom {
		from = to.Add(-defaultSpan)
	}
	if from.After(to) {
		return 0, 0, paramErr("invalid_parameter", "from doit précéder to")
	}
	return from.UnixMilli(), to.UnixMilli(), nil
}

func intParam(v url.Values, name string, def, min, max int) (int, error) {
	raw := v.Get(name)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		return 0, paramErr("invalid_parameter", "paramètre %s : entier entre %d et %d attendu", name, min, max)
	}
	return n, nil
}

func deviceParam(v url.Values, required bool) (string, error) {
	d := v.Get("device_id")
	if d == "" {
		if required {
			return "", paramErr("missing_parameter", "paramètre device_id requis")
		}
		return "", nil
	}
	if !validDeviceID(d) {
		return "", paramErr("invalid_parameter", "device_id invalide")
	}
	return d, nil
}

var typePrefixRe = regexp.MustCompile(`^[a-z0-9_.]{1,64}$`)

// typePrefixes parses the "type" parameter: comma-separated type prefixes.
func typePrefixes(v url.Values) ([]string, error) {
	var out []string
	for _, p := range strings.Split(v.Get("type"), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !typePrefixRe.MatchString(p) || len(out) >= 32 {
			return nil, paramErr("invalid_parameter", "paramètre type : préfixes [a-z0-9_.] séparés par des virgules")
		}
		out = append(out, p)
	}
	return out, nil
}

// packageRe matches an Android package name (or a similar identifier).
var packageRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,255}$`)

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	devs, err := s.st.DeviceSummaries(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devs})
}

func encodeCursor(ts, pk int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(ts, 10) + "." + strconv.FormatInt(pk, 10)))
}

func decodeCursor(c string) (int64, int64, bool) {
	if len(c) > 64 {
		return 0, 0, false
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, 0, false
	}
	a, p, ok := strings.Cut(string(b), ".")
	if !ok {
		return 0, 0, false
	}
	ts, err1 := strconv.ParseInt(a, 10, 64)
	pk, err2 := strconv.ParseInt(p, 10, 64)
	return ts, pk, err1 == nil && err2 == nil
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	var q store.EventQuery
	var err error
	if q.DeviceID, err = deviceParam(v, false); err != nil {
		s.fail(w, err)
		return
	}
	if q.FromMS, q.ToMS, err = timeRange(v, true, s.now(), 0); err != nil {
		s.fail(w, err)
		return
	}
	if q.TypePrefixes, err = typePrefixes(v); err != nil {
		s.fail(w, err)
		return
	}
	if q.SevMin, err = intParam(v, "sev_min", 0, 0, 3); err != nil {
		s.fail(w, err)
		return
	}
	if q.Limit, err = intParam(v, "limit", 100, 1, 500); err != nil {
		s.fail(w, err)
		return
	}
	q.Q = v.Get("q")
	if len(q.Q) > 200 {
		s.fail(w, paramErr("invalid_parameter", "paramètre q : 200 octets au plus"))
		return
	}
	if c := v.Get("cursor"); c != "" {
		ts, pk, ok := decodeCursor(c)
		if !ok {
			s.fail(w, paramErr("invalid_parameter", "curseur invalide"))
			return
		}
		q.HasCursor, q.CursorTS, q.CursorPK = true, ts, pk
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	evs, more, err := s.st.QueryEvents(ctx, q)
	if err != nil {
		s.fail(w, err)
		return
	}
	if evs == nil {
		evs = []store.StoredEvent{}
	}
	resp := map[string]any{"events": evs}
	if more && len(evs) > 0 {
		resp["next_cursor"] = encodeCursor(evs[len(evs)-1].TSms, evs[len(evs)-1].PK)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(r.PathValue("id"))
	if len(id) != 26 {
		writeError(w, http.StatusNotFound, "not_found", "événement introuvable")
		return
	}
	ev, err := s.st.GetEvent(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (s *Server) handleLocations(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	dev, err := deviceParam(v, false)
	if err != nil {
		s.fail(w, err)
		return
	}
	from, to, err := timeRange(v, true, s.now(), 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	maxPoints, err := intParam(v, "max_points", 2000, 1, 20000)
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	pts, err := s.st.Locations(ctx, dev, from, to, maxPoints)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": pts})
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	var q store.TimelineQuery
	var err error
	if q.DeviceID, err = deviceParam(v, false); err != nil {
		s.fail(w, err)
		return
	}
	if q.FromMS, q.ToMS, err = timeRange(v, true, s.now(), 0); err != nil {
		s.fail(w, err)
		return
	}
	switch v.Get("bucket") {
	case "minute":
		q.BucketMS = int64(time.Minute / time.Millisecond)
	case "", "hour":
		q.BucketMS = int64(time.Hour / time.Millisecond)
	case "day":
		q.BucketMS = int64(24 * time.Hour / time.Millisecond)
	default:
		s.fail(w, paramErr("invalid_parameter", "bucket : minute, hour ou day"))
		return
	}
	if q.TypePrefixes, err = typePrefixes(v); err != nil {
		s.fail(w, err)
		return
	}
	switch by := v.Get("by"); by {
	case "", "domain":
		q.By = "domain"
	case "type", "sev":
		q.By = by
	default:
		s.fail(w, paramErr("invalid_parameter", "by : domain, type ou sev"))
		return
	}
	if q.FromMS < 0 {
		s.fail(w, paramErr("invalid_parameter", "from antérieur à 1970"))
		return
	}
	if n := (q.ToMS-(q.FromMS-q.FromMS%q.BucketMS))/q.BucketMS + 1; n > store.MaxTimelineBuckets {
		s.fail(w, paramErr("too_many_buckets", "intervalle trop long pour ce pas (%d intervalles au plus)", store.MaxTimelineBuckets))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	tl, err := s.st.StatsTimeline(ctx, q)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tl)
}

func (s *Server) handleTop(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	dev, err := deviceParam(v, false)
	if err != nil {
		s.fail(w, err)
		return
	}
	from, to, err := timeRange(v, true, s.now(), 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	kind := v.Get("kind")
	if !store.ValidTopKind(kind) {
		s.fail(w, paramErr("invalid_parameter", "kind : dns_hostname, dns_package, connect_dest, connect_package, usage_package, foreground_package, notification_package ou event_type"))
		return
	}
	limit, err := intParam(v, "limit", 20, 1, 500)
	if err != nil {
		s.fail(w, err)
		return
	}
	pkg := v.Get("package")
	if pkg != "" && (!packageRe.MatchString(pkg) || kind == store.TopEventType) {
		s.fail(w, paramErr("invalid_parameter", "paramètre package invalide (non applicable à kind=event_type)"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	items, err := s.st.StatsTop(ctx, dev, kind, pkg, from, to, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	dev, err := deviceParam(r.URL.Query(), true)
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	snap, err := s.st.LatestApps(ctx, dev)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	dev, err := deviceParam(v, true)
	if err != nil {
		s.fail(w, err)
		return
	}
	from, to, err := timeRange(v, false, s.now(), 30*24*time.Hour)
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	ans, err := s.st.Posture(ctx, dev, from, to, 500)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ans)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	// from/to are optional here (default: the last 7 days).
	from, to, err := timeRange(v, false, s.now(), 7*24*time.Hour)
	if err != nil {
		s.fail(w, err)
		return
	}
	levelMin, err := intParam(v, "level_min", 0, 0, 16)
	if err != nil {
		s.fail(w, err)
		return
	}
	limit, err := intParam(v, "limit", 100, 1, 500)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.alerts.Search(r.Context(), s.log, from, to, levelMin, limit))
}
