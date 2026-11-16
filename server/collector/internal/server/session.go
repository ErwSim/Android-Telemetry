package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/auth"
	"github.com/erwsim/watchpost/server/collector/internal/store"
)

const (
	sessionIdle     = 12 * time.Hour
	sessionLifetime = 7 * 24 * time.Hour
	sessionTouch    = 5 * time.Minute
	csrfHeader      = "X-Requested-With"
	csrfValue       = "watchpost"
)

type ctxKey int

const userKey ctxKey = 1

func (s *Server) cookieName() string {
	if s.cfg.CookieSecure {
		return "__Host-watchpost_session" // requires Secure, Path=/ and no Domain
	}
	return "watchpost_session"
}

func hashSessionToken(t string) []byte {
	sum := sha256.Sum256([]byte(t))
	return sum[:]
}

// csrf requires the X-Requested-With: watchpost header on state-changing requests.
// A cross-site form cannot set it, and a cross-site fetch setting it needs a
// CORS preflight that this server never approves.
func (s *Server) csrf(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(csrfHeader) != csrfValue {
			writeError(w, http.StatusForbidden, "csrf", "en-tête X-Requested-With: watchpost requis")
			return
		}
		next(w, r)
	}
}

// currentUser returns the user of a valid session cookie.
func (s *Server) currentUser(r *http.Request) (string, []byte, bool) {
	c, err := r.Cookie(s.cookieName())
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return "", nil, false
	}
	h := hashSessionToken(c.Value)
	now := s.now()
	sess, err := s.st.GetSession(r.Context(), h, now)
	if err != nil {
		return "", nil, false
	}
	if now.Sub(sess.LastSeen) > sessionIdle {
		_ = s.st.DeleteSession(context.WithoutCancel(r.Context()), h)
		return "", nil, false
	}
	if now.Sub(sess.LastSeen) > sessionTouch {
		_ = s.st.TouchSession(r.Context(), h, now)
	}
	return sess.Username, h, true
}

// auth requires a valid session (and the CSRF header for non-GET methods).
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(csrfHeader) != csrfValue {
			writeError(w, http.StatusForbidden, "csrf", "en-tête X-Requested-With: watchpost requis")
			return
		}
		user, _, ok := s.currentUser(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized", "session absente ou expirée")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey, user)))
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	// Every attempt takes its token before any verification and gets it back
	// only when it did not count. Checking first and charging after the slow
	// password hash would let concurrent attempts all pass the check.
	if ok, wait := s.loginIP.Allow(ip); !ok {
		writeRetry(w, wait, "trop de tentatives de connexion")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		s.loginIP.Refund(ip)
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "requête trop volumineuse")
		return
	}
	var req loginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.loginIP.Refund(ip)
		writeError(w, http.StatusBadRequest, "invalid_json", "JSON { username, password } attendu")
		return
	}
	if !auth.ValidUsername(req.Username) || req.Password == "" || len(req.Password) > auth.MaxPasswordLen {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "identifiants invalides")
		return
	}
	if ok, wait := s.loginUser.Allow(req.Username); !ok {
		s.loginIP.Refund(ip)
		writeRetry(w, wait, "trop de tentatives de connexion pour ce compte")
		return
	}
	refund := func() {
		s.loginIP.Refund(ip)
		s.loginUser.Refund(req.Username)
	}

	// Bound concurrent argon2 computations (64 MiB each).
	select {
	case s.hashSlots <- struct{}{}:
	case <-r.Context().Done():
		refund()
		return
	case <-time.After(10 * time.Second):
		refund()
		writeRetry(w, 5*time.Second, "serveur occupé")
		return
	}
	user, err := s.st.GetUser(r.Context(), req.Username)
	hash := auth.DummyHash()
	if err == nil {
		hash = user.PasswordHash
	} else if !errors.Is(err, store.ErrNotFound) {
		<-s.hashSlots
		refund()
		s.log.Error("connexion : lecture du compte impossible", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "service momentanément indisponible")
		return
	}
	ok, verr := auth.VerifyPassword(req.Password, hash)
	<-s.hashSlots
	if verr != nil {
		s.log.Error("connexion : empreinte de mot de passe illisible", "username", req.Username)
	}
	if user == nil || !ok {
		s.log.Warn("échec de connexion à la console", "username", req.Username, "ip", ip)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "identifiants invalides")
		return
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "erreur interne")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now()
	expires := now.Add(sessionLifetime)
	if err := s.st.CreateSession(r.Context(), hashSessionToken(token), user.Username, now, expires); err != nil {
		s.log.Error("connexion : création de session impossible", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "service momentanément indisponible")
		return
	}
	s.loginUser.Reset(req.Username)
	s.loginIP.Refund(ip)
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: token, Path: "/", Expires: expires, MaxAge: int(sessionLifetime.Seconds()),
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
	s.log.Info("connexion à la console", "username", user.Username, "ip", ip)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if _, h, ok := s.currentUser(r); ok {
		_ = s.st.DeleteSession(r.Context(), h)
	}
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userKey).(string)
	writeJSON(w, http.StatusOK, map[string]string{"username": user})
}
