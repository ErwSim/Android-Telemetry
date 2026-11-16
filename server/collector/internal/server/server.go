// Package server implements the HTTP side of the collector: ingestion API
// (contract §3), console API (§6), console files and health check.
package server

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/config"
	"github.com/erwsim/watchpost/server/collector/internal/detect"
	"github.com/erwsim/watchpost/server/collector/internal/export"
	"github.com/erwsim/watchpost/server/collector/internal/ratelimit"
	"github.com/erwsim/watchpost/server/collector/internal/store"
)

// Server holds the HTTP handlers and their dependencies.
type Server struct {
	cfg      *config.Config
	st       *store.Store
	log      *slog.Logger
	exporter *export.Exporter // nil when export is disabled
	broker   *Broker
	cmdHub   *cmdHub
	tracking *trackingService
	detector *detect.Engine
	alerts   *AlertsClient
	static   http.Handler
	csp      string
	now      func() time.Time

	ingestAuthFail *ratelimit.Limiter // per client IP, failed device authentications
	ingestDevice   *ratelimit.Limiter // per device, requests
	ingestSlots    chan struct{}      // concurrent ingestion requests
	loginIP        *ratelimit.Limiter // per client IP, failed logins
	loginUser      *ratelimit.Limiter // per username, failed logins
	hashSlots      chan struct{}      // concurrent argon2 computations
}

// Options are the optional dependencies of New.
type Options struct {
	Exporter  *export.Exporter
	ConsoleFS fs.FS // console files (index.html at the root)
	Now       func() time.Time
}

// New builds a server.
func New(cfg *config.Config, st *store.Store, log *slog.Logger, opt Options) (*Server, error) {
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	alerts, err := NewAlertsClient(cfg)
	if err != nil {
		return nil, err
	}
	// Events carry their origin ts (hours or days old for after-the-fact logs): the store drops
	// those older than the retention window, which the purge would delete anyway.
	st.SetRetention(time.Duration(cfg.RetentionDays) * 24 * time.Hour)
	s := &Server{
		cfg: cfg, st: st, log: log, exporter: opt.Exporter, broker: NewBroker(64), cmdHub: newCmdHub(cmdMaxStreams),
		alerts: alerts, csp: buildCSP(cfg.TileOrigin), now: now,
		ingestAuthFail: ratelimit.New(1.0/30, 10, 100000),
		ingestDevice:   ratelimit.New(5, 60, 10000),
		ingestSlots:    make(chan struct{}, 8),
		loginIP:        ratelimit.New(1.0/60, 10, 100000),
		loginUser:      ratelimit.New(1.0/60, 10, 10000),
		hashSlots:      make(chan struct{}, 2),
	}
	if s.tracking, err = newTrackingService(s); err != nil {
		return nil, err
	}
	s.detector = s.newDetector()
	if opt.ConsoleFS != nil {
		s.static = newStaticHandler(opt.ConsoleFS)
	} else {
		s.static = http.NotFoundHandler()
	}
	return s, nil
}

// Broker returns the live event broker (SSE).
func (s *Server) Broker() *Broker { return s.broker }

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Ingestion (phone -> server). The only things sent back to the agent are acknowledgements and the
	// commands of the closed list of contract §8 (never configuration nor policy).
	mux.HandleFunc("POST /api/v1/ingest", s.handleIngest)
	mux.HandleFunc("GET /api/v1/ping", s.handlePing)
	mux.HandleFunc("GET /api/v1/commands/stream", s.handleCommandStream)
	mux.HandleFunc("GET /api/v1/commands", s.handleCommandPoll)
	mux.HandleFunc("POST /api/v1/commands/{id}/result", s.handleCommandResult)
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "unknown API endpoint")
	})

	// Console API.
	mux.HandleFunc("POST /api/console/login", s.csrf(s.handleLogin))
	mux.HandleFunc("POST /api/console/logout", s.csrf(s.handleLogout))
	mux.HandleFunc("GET /api/console/me", s.auth(s.handleMe))
	mux.HandleFunc("GET /api/console/devices", s.auth(s.handleDevices))
	mux.HandleFunc("GET /api/console/events", s.auth(s.handleEvents))
	mux.HandleFunc("GET /api/console/events/{id}", s.auth(s.handleEvent))
	mux.HandleFunc("GET /api/console/locations", s.auth(s.handleLocations))
	mux.HandleFunc("GET /api/console/stats/timeline", s.auth(s.handleTimeline))
	mux.HandleFunc("GET /api/console/stats/top", s.auth(s.handleTop))
	mux.HandleFunc("GET /api/console/apps", s.auth(s.handleApps))
	mux.HandleFunc("GET /api/console/apps/risk", s.auth(s.handleAppsRisk))
	mux.HandleFunc("GET /api/console/apps/ops", s.auth(s.handleAppsOps))
	mux.HandleFunc("GET /api/console/detections", s.auth(s.handleDetections))
	mux.HandleFunc("GET /api/console/detections/mutes", s.auth(s.handleMutes))
	mux.HandleFunc("POST /api/console/detections/mute", s.auth(s.handleMute))
	mux.HandleFunc("DELETE /api/console/detections/mute", s.auth(s.handleUnmute))
	mux.HandleFunc("GET /api/console/posture", s.auth(s.handlePosture))
	mux.HandleFunc("GET /api/console/alerts", s.auth(s.handleAlerts))
	mux.HandleFunc("GET /api/console/stream", s.auth(s.handleStream))
	mux.HandleFunc("GET /api/console/commands", s.auth(s.handleListCommands))
	mux.HandleFunc("POST /api/console/commands", s.auth(s.handleCreateCommand))
	mux.HandleFunc("POST /api/console/commands/{id}/cancel", s.auth(s.handleCancelCommand))
	mux.HandleFunc("GET /api/console/tracking/summary", s.auth(s.handleTrackingSummary))
	mux.HandleFunc("GET /api/console/tracking/domains", s.auth(s.handleTrackingDomains))
	mux.HandleFunc("GET /api/console/tracking/apps", s.auth(s.handleTrackingApps))
	mux.HandleFunc("PUT /api/console/tracking/override", s.auth(s.handleTrackingOverride))
	mux.HandleFunc("GET /api/console/tracking/level", s.auth(s.handleTrackingLevelGet))
	mux.HandleFunc("PUT /api/console/tracking/level", s.auth(s.handleTrackingLevelPut))
	mux.HandleFunc("/api/console/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "unknown API endpoint")
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "unknown API endpoint")
	})

	mux.HandleFunc("GET /healthz", s.handleHealth)
	// Runtime configuration of the console; takes precedence over its static file.
	mux.HandleFunc("GET /config.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"tileUrl": s.cfg.TileURL})
	})
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.static.ServeHTTP(w, r)
	}))

	return s.withCommon(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.st.Ping(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("database unavailable\n"))
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}

// NewHTTPServer returns an http.Server with conservative timeouts.
func (s *Server) NewHTTPServer(baseCtx context.Context) *http.Server {
	return &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second, // SSE extends its own deadline per write
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

// RunRetention purges old data every interval until ctx is canceled.
func (s *Server) RunRetention(ctx context.Context, interval time.Duration) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := s.now()
		cutoff := now.Add(-time.Duration(s.cfg.RetentionDays) * 24 * time.Hour)
		res, err := s.st.Purge(ctx, cutoff, now, sessionIdle)
		switch {
		case err != nil && !errors.Is(err, context.Canceled):
			s.log.Error("retention purge failed", "err", err)
		case res.Events > 0:
			s.log.Info("retention purge", "events", res.Events, "cutoff", cutoff.UTC().Format(time.RFC3339))
		}
		t.Reset(interval)
	}
}
