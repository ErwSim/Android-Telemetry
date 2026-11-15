package server

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
)

// apiError is the error body of every JSON API (contract §6).
type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := model.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		b = []byte(`{"error":"internal","message":"encodage de la réponse impossible"}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: code, Message: msg})
}

func writeRetry(w http.ResponseWriter, wait time.Duration, msg string) {
	secs := int(wait.Seconds() + 0.999)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, "rate_limited", msg)
}

// remoteAddr returns the address of the TCP peer.
func remoteAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func (s *Server) isTrusted(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// fromTrustedProxy reports whether the request comes directly from a trusted proxy.
func (s *Server) fromTrustedProxy(r *http.Request) bool { return s.isTrusted(remoteAddr(r)) }

// clientIP returns the client address: the TCP peer, or, when the peer is a
// trusted proxy, the right-most X-Forwarded-For entry that is not a trusted proxy.
func (s *Server) clientIP(r *http.Request) string {
	peer := remoteAddr(r)
	if !s.isTrusted(peer) {
		return peer.String()
	}
	var parts []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		parts = append(parts, strings.Split(v, ",")...)
	}
	for i := len(parts) - 1; i >= 0 && i >= len(parts)-16; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !s.isTrusted(a) {
			return a.String()
		}
	}
	return peer.String()
}

// statusRecorder captures the response status for access logs.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer (SSE flush, deadlines).
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// withCommon adds panic recovery, security headers and access logs.
func (s *Server) withCommon(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panique dans un gestionnaire HTTP", "path", r.URL.Path, "panic", v, "stack", string(debug.Stack()))
				if rec.status == 0 {
					writeError(rec, http.StatusInternalServerError, "internal", "erreur interne")
				}
			}
			// Paths only: query strings may contain search text; never log headers (tokens, cookies).
			lvl := slog.LevelDebug
			if rec.status >= 500 || (rec.status >= 400 && strings.HasPrefix(r.URL.Path, "/api/v1/")) {
				lvl = slog.LevelInfo
			}
			s.log.Log(r.Context(), lvl, "http", "method", r.Method, "path", r.URL.Path, "status", rec.status,
				"ms", time.Since(start).Milliseconds(), "ip", s.clientIP(r))
		}()
		h := rec.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=()")
		if s.cfg.CookieSecure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		} else {
			h.Set("Content-Security-Policy", s.csp)
		}
		next.ServeHTTP(rec, r)
	})
}

// buildCSP returns the policy of the console pages: no inline script, no CDN;
// map tiles may come from the configured origins (MapLibre also needs blob: workers).
func buildCSP(tileOrigins []string) string {
	tiles := strings.Join(tileOrigins, " ")
	if tiles != "" {
		tiles = " " + tiles
	}
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob:" + tiles,
		"connect-src 'self'" + tiles,
		"font-src 'self' data:",
		"worker-src 'self' blob:",
		"child-src 'self' blob:",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	}, "; ")
}

func validDeviceID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
