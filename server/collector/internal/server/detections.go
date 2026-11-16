package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/erwsim/android-telemetry/server/collector/internal/detect"
	"github.com/erwsim/android-telemetry/server/collector/internal/model"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

// Behavioral detections (contract §11.3): computed in the background by detect.Engine from the aggregates,
// stored once per window and subject, exported to Wazuh and streamed as events of the collector (source
// "server", type detect.*); the console lists them with GET /detections and shows the risk profile and the
// operations of the applications (GET /apps/risk, GET /apps/ops).

func (s *Server) newDetector() *detect.Engine {
	return detect.NewEngine(s.st, s.cfg.Detect, detect.Options{
		AdGuardClients: s.cfg.AdGuardClients,
		ThreatLists:    len(s.tracking.threats) > 0,
		Log:            s.log,
		Publish:        s.published,
		Now:            s.now,
		Retention:      time.Duration(s.cfg.RetentionDays) * 24 * time.Hour,
	})
}

// StartDetections evaluates the detections every VIGIE_DETECT_INTERVAL_S until ctx is canceled.
func (s *Server) StartDetections(ctx context.Context) {
	if !s.cfg.DetectEnabled {
		s.log.Info("détections désactivées (VIGIE_DETECT_ENABLED=false)")
		return
	}
	var off []string
	for _, t := range detect.Types {
		if !s.cfg.Detect.Enabled(t) {
			off = append(off, t)
		}
	}
	s.log.Info("détections actives", "interval", s.cfg.DetectInterval.String(), "disabled", off)
	if s.tracking.client != nil && len(s.tracking.threats) == 0 {
		s.log.Warn("détections : aucune liste de catégorie \"threat\" dans VIGIE_ADGUARD_LEVELS_FILE, detect.threat_domain reste muette")
	}
	go s.detector.Run(ctx, s.cfg.DetectInterval)
}

const defaultDetectionSpan = 30 * 24 * time.Hour

func (s *Server) handleDetections(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	var q store.DetectionQuery
	var err error
	if q.DeviceID, err = deviceParam(v, false); err != nil {
		s.fail(w, err)
		return
	}
	// from/to are optional here (default: the last 30 days); they bound the time of the finding.
	if q.FromMS, q.ToMS, err = timeRange(v, false, s.now(), defaultDetectionSpan); err != nil {
		s.fail(w, err)
		return
	}
	if q.TypePrefixes, err = typePrefixes(v); err != nil {
		s.fail(w, err)
		return
	}
	if q.Package = v.Get("package"); q.Package != "" && !packageRe.MatchString(q.Package) {
		s.fail(w, paramErr("invalid_parameter", "paramètre package invalide"))
		return
	}
	if q.Limit, err = intParam(v, "limit", 100, 1, 500); err != nil {
		s.fail(w, err)
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
	items, more, err := s.st.ListDetections(ctx, q)
	if err != nil {
		s.fail(w, err)
		return
	}
	resp := map[string]any{"detections": items}
	if more && len(items) > 0 {
		last := items[len(items)-1]
		resp["next_cursor"] = encodeCursor(last.TSms, last.PK)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAppsRisk(w http.ResponseWriter, r *http.Request) {
	dev, err := deviceParam(r.URL.Query(), true)
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	latest, err := s.st.AppLatest(ctx, dev, store.AppLatestRisk)
	if err != nil {
		s.fail(w, err)
		return
	}
	type item struct {
		score int64
		pkg   string
		v     map[string]any
	}
	items := make([]item, 0, len(latest))
	for pkg, ev := range latest {
		var m map[string]any
		if json.Unmarshal(ev.Data, &m) != nil || m == nil {
			continue
		}
		m["package"] = pkg
		m["ts"] = model.FormatMS(ev.TSms)
		score, _ := model.Int(m, "score")
		items = append(items, item{score: score, pkg: pkg, v: m})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].pkg < items[j].pkg
	})
	out := make([]map[string]any, len(items))
	for i, it := range items {
		out[i] = it.v
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}

// appOps is one application of GET /apps/ops.
type appOps struct {
	Package    string      `json:"package"`
	Label      string      `json:"label,omitempty"`
	Count      int64       `json:"count"`
	Background int64       `json:"background_count"`
	Rejected   int64       `json:"rejected_count"`
	LastTS     string      `json:"last_ts,omitempty"`
	Ops        []opsDetail `json:"ops"`
	last       int64
}

type opsDetail struct {
	Op         string `json:"op"`
	Count      int64  `json:"count"`
	Background int64  `json:"background_count"`
	Rejected   int64  `json:"rejected_count"`
	LastTS     string `json:"last_ts,omitempty"`
}

func (s *Server) handleAppsOps(w http.ResponseWriter, r *http.Request) {
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
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	// Hourly aggregates: the hours overlapping [from, to].
	uses, err := s.st.OpsUses(ctx, dev, from-mod(from, 3600000), to+1)
	if err != nil {
		s.fail(w, err)
		return
	}
	labels, err := s.st.AppLabels(ctx, dev)
	if err != nil {
		s.fail(w, err)
		return
	}
	byPkg := map[string]*appOps{}
	for _, u := range uses {
		a := byPkg[u.Package]
		if a == nil {
			a = &appOps{Package: u.Package, Label: labels[u.Package], Ops: []opsDetail{}}
			byPkg[u.Package] = a
		}
		d := opsDetail{Op: u.Op, Count: u.Count, Background: u.Background, Rejected: u.Rejected}
		if u.LastMS > 0 {
			d.LastTS = model.FormatMS(u.LastMS)
		}
		a.Ops = append(a.Ops, d)
		a.Count += u.Count
		a.Background += u.Background
		a.Rejected += u.Rejected
		if u.LastMS > a.last {
			a.last, a.LastTS = u.LastMS, d.LastTS
		}
	}
	out := make([]*appOps, 0, len(byPkg))
	for _, a := range byPkg {
		sort.Slice(a.Ops, func(i, j int) bool {
			if a.Ops[i].Count != a.Ops[j].Count {
				return a.Ops[i].Count > a.Ops[j].Count
			}
			return a.Ops[i].Op < a.Ops[j].Op
		})
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Package < out[j].Package
	})
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}

func mod(a, b int64) int64 {
	m := a % b
	if m < 0 {
		m += b
	}
	return m
}

// muteRequest reads the body of POST and DELETE /detections/mute: device_id, type, package, reason.
func (s *Server) muteRequest(w http.ResponseWriter, r *http.Request) (store.Mute, bool) {
	var m store.Mute
	fields, ok := readStrictBody(w, r, "device_id", "type", "package", "reason")
	if !ok {
		return m, false
	}
	var ok1, ok2, ok3 bool
	m.DeviceID, ok1 = jsonString(fields["device_id"])
	m.Type, ok2 = jsonString(fields["type"])
	m.Package, ok3 = jsonString(fields["package"])
	if raw, present := fields["reason"]; present {
		var okR bool
		if m.Reason, okR = jsonString(raw); !okR {
			writeError(w, http.StatusBadRequest, "invalid_json", "reason : chaîne attendue")
			return m, false
		}
	}
	switch {
	case !ok1 || !validDeviceID(m.DeviceID):
		writeError(w, http.StatusBadRequest, "invalid_parameter", "device_id invalide")
	case !ok3 || !packageRe.MatchString(m.Package):
		writeError(w, http.StatusBadRequest, "invalid_parameter", "package : nom de paquet requis")
	case !ok2 || !knownDetection(m.Type):
		writeError(w, http.StatusBadRequest, "invalid_parameter", "type : type de détection inconnu")
	case !store.Mutable(m.Type):
		writeError(w, http.StatusBadRequest, "not_mutable", m.Type+" ne peut pas être mise en sourdine")
	case len([]rune(m.Reason)) > 200 || strings.IndexFunc(m.Reason, unicode.IsControl) >= 0:
		writeError(w, http.StatusBadRequest, "invalid_parameter", "reason : 200 caractères au plus, sans caractère de contrôle")
	default:
		m.CreatedBy, _ = r.Context().Value(userKey).(string)
		return m, true
	}
	return m, false
}

func knownDetection(t string) bool {
	for _, x := range detect.Types {
		if x == t {
			return true
		}
	}
	return false
}

// handleMute: POST /detections/mute (contract §11.4). The detections of (device, type, package) are still
// computed and stored, with muted: true, but neither exported nor streamed. Idempotent (a second call only
// replaces the reason); detect.muted is recorded when the mute is new.
func (s *Server) handleMute(w http.ResponseWriter, r *http.Request) {
	m, ok := s.muteRequest(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	ev, err := s.st.SetMute(ctx, m, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	if ev != nil {
		s.published([]store.StoredEvent{*ev})
		s.log.Info("détections mises en sourdine", "device_id", m.DeviceID, "type", m.Type, "package", m.Package, "user", m.CreatedBy)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// handleUnmute: DELETE /detections/mute, same body; 404 when there is no such mute.
func (s *Server) handleUnmute(w http.ResponseWriter, r *http.Request) {
	m, ok := s.muteRequest(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	ev, err := s.st.DeleteMute(ctx, m.DeviceID, m.Type, m.Package, m.CreatedBy, m.Reason, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.published([]store.StoredEvent{*ev})
	s.log.Info("sourdine levée", "device_id", m.DeviceID, "type", m.Type, "package", m.Package, "user", m.CreatedBy)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMutes(w http.ResponseWriter, r *http.Request) {
	dev, err := deviceParam(r.URL.Query(), false)
	if err != nil {
		s.fail(w, err)
		return
	}
	mutes, err := s.st.ListMutes(r.Context(), dev)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mutes": mutes})
}
