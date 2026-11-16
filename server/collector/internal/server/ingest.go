package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/enroll"
	"github.com/erwsim/watchpost/server/collector/internal/model"
	"github.com/erwsim/watchpost/server/collector/internal/pki"
	"github.com/erwsim/watchpost/server/collector/internal/store"
)

// Ingestion limits (contract §3).
const (
	MaxBatchEvents     = 500
	MaxCompressedBytes = 1 << 20
	MaxDecodedBytes    = 8 << 20
	maxTokenLen        = 512
)

// CertHeader carries the SHA-256 of the verified client certificate, set by Caddy.
const CertHeader = "X-Watchpost-Client-Cert-Sha256"

var errUnauthorized = errors.New("unauthorized")

// authenticateDevice checks the bearer token and the client certificate fingerprint.
// Every failure returns the same error so the response leaks nothing.
func (s *Server) authenticateDevice(r *http.Request) (*store.Device, error) {
	authz := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(authz, "Bearer ")
	token = strings.TrimSpace(token)
	if !ok || token == "" || len(token) > maxTokenLen {
		return nil, errUnauthorized
	}
	h := enroll.HashToken(token)
	dev, err := s.st.DeviceByTokenHash(r.Context(), h)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errUnauthorized
		}
		return nil, err
	}
	if dev.Revoked() {
		return nil, errUnauthorized
	}
	// The token and the certificate must belong to the same credential pair: the old token goes with the
	// old certificate, the pending token with the pending certificate, never a mix.
	wantFP := dev.CertSHA256
	if dev.ViaPending {
		wantFP = dev.NextCertSHA256
	}
	// The fingerprint header is only believed when it comes from a trusted proxy.
	fp := ""
	if s.fromTrustedProxy(r) {
		fp = pki.NormalizeFingerprint(r.Header.Get(CertHeader))
		if fp == "" && r.Header.Get(CertHeader) != "" {
			return nil, errUnauthorized
		}
	}
	if fp == "" {
		if s.cfg.RequireClientCert {
			return nil, errUnauthorized
		}
		return dev, nil
	}
	if subtle.ConstantTimeCompare([]byte(fp), []byte(wantFP)) != 1 {
		return nil, errUnauthorized
	}
	return dev, nil
}

// deviceAuth runs the common authentication and rate limiting of /api/v1.
func (s *Server) deviceAuth(w http.ResponseWriter, r *http.Request) (*store.Device, bool) {
	ip := s.clientIP(r)
	if blocked, wait := s.ingestAuthFail.Blocked(ip); blocked {
		writeRetry(w, wait, "trop d'échecs d'authentification")
		return nil, false
	}
	dev, err := s.authenticateDevice(r)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			s.ingestAuthFail.Consume(ip)
			writeError(w, http.StatusUnauthorized, "unauthorized", "jeton, certificat ou appareil invalide")
			return nil, false
		}
		s.log.Error("authentification d'appareil : erreur de base", "err", err)
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, "unavailable", "service momentanément indisponible")
		return nil, false
	}
	if ok, wait := s.ingestDevice.Allow(dev.DeviceID); !ok {
		writeRetry(w, wait, "débit maximal atteint pour cet appareil")
		return nil, false
	}
	return dev, true
}

// commitRenewal makes the pending credential pair current once a request authenticated with it is fully
// validated (contract §4): from then on the previous token and certificate are refused. A failure only
// delays the switch, the request itself is valid.
func (s *Server) commitRenewal(ctx context.Context, dev *store.Device) {
	if !dev.ViaPending {
		return
	}
	ctx = context.WithoutCancel(ctx)
	switched, err := s.st.PromotePending(ctx, dev.DeviceID, dev.NextTokenHash)
	if err != nil {
		s.log.Warn("renouvellement : bascule impossible, réessayée au prochain envoi", "device_id", dev.DeviceID, "err", err)
		return
	}
	if switched {
		s.log.Info("renouvellement : nouveau jeton et nouveau certificat en service, anciens refusés", "device_id", dev.DeviceID)
	}
}

type ingestRequest struct {
	DeviceID     string            `json:"device_id"`
	AgentVersion string            `json:"agent_version"`
	SentAt       string            `json:"sent_at"`
	Events       []json.RawMessage `json:"events"`
}

type rejection struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type ingestResponse struct {
	Accepted   int         `json:"accepted"`
	Duplicates int         `json:"duplicates"`
	Rejected   []rejection `json:"rejected"`
	ServerTime string      `json:"server_time"`
}

// parseBatch reads the batch envelope. Events stay raw and are not nested-depth checked here: with
// json.Unmarshal, one event nested beyond encoding/json's limit (10000 levels) would make the whole batch
// unreadable, a 400 for a defect of a single event (contract §3: that event belongs in "rejected").
// Only a real envelope defect (invalid JSON, wrong field types, trailing data, "events" not an array) fails.
func parseBatch(raw []byte) (*ingestRequest, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("lot : objet JSON attendu")
	}
	var req ingestRequest
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch k {
		case "device_id":
			err = dec.Decode(&req.DeviceID)
		case "agent_version":
			err = dec.Decode(&req.AgentVersion)
		case "sent_at":
			err = dec.Decode(&req.SentAt)
		case "events":
			req.Events, err = parseEvents(dec, raw)
		default:
			err = model.SkipValue(dec)
		}
		if err != nil {
			return nil, err
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errors.New("lot : objet JSON mal terminé")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("lot : données après l'objet JSON")
	}
	return &req, nil
}

// parseEvents reads the "events" value: null gives nil (missing), an array gives its raw elements.
func parseEvents(dec *json.Decoder, raw []byte) ([]json.RawMessage, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, nil
	}
	if tok != json.Delim('[') {
		return nil, errors.New("lot : events doit être un tableau")
	}
	evs := []json.RawMessage{}
	for dec.More() {
		start := dec.InputOffset()
		if err := model.SkipValue(dec); err != nil {
			return nil, err
		}
		el := bytes.TrimSpace(raw[start:dec.InputOffset()])
		el = bytes.TrimSpace(bytes.TrimPrefix(el, []byte(",")))
		evs = append(evs, json.RawMessage(el))
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
		return nil, errors.New("lot : tableau events mal terminé")
	}
	return evs, nil
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.deviceAuth(w, r)
	if !ok {
		return
	}
	select {
	case s.ingestSlots <- struct{}{}:
		defer func() { <-s.ingestSlots }()
	default:
		writeRetry(w, 2*time.Second, "serveur occupé")
		return
	}

	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type application/json attendu")
		return
	}
	var body io.Reader
	var wire *errTracker
	switch enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc {
	case "gzip":
		wire = &errTracker{r: http.MaxBytesReader(w, r.Body, MaxCompressedBytes)}
		zr, err := gzip.NewReader(wire)
		if err != nil {
			if wire.tooLarge() {
				writeError(w, http.StatusRequestEntityTooLarge, "too_large", "lot compressé supérieur à 1 Mio")
				return
			}
			writeError(w, http.StatusBadRequest, "invalid_gzip", "flux gzip invalide")
			return
		}
		defer zr.Close()
		body = io.LimitReader(zr, MaxDecodedBytes+1)
	case "", "identity":
		body = http.MaxBytesReader(w, r.Body, MaxDecodedBytes)
	default:
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_encoding", "Content-Encoding gzip ou absent attendu")
		return
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		if tooLarge(err) || (wire != nil && wire.tooLarge()) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "lot trop volumineux")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_body", "corps illisible ou gzip invalide")
		return
	}
	if len(raw) > MaxDecodedBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "lot décompressé supérieur à 8 Mio")
		return
	}

	req, err := parseBatch(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "lot JSON invalide")
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.DeviceID), []byte(dev.DeviceID)) != 1 {
		s.ingestAuthFail.Consume(s.clientIP(r))
		writeError(w, http.StatusUnauthorized, "unauthorized", "device_id ne correspond pas au jeton")
		return
	}
	s.commitRenewal(r.Context(), dev)
	if req.Events == nil {
		writeError(w, http.StatusBadRequest, "invalid_batch", "champ events manquant")
		return
	}
	if len(req.Events) > MaxBatchEvents {
		writeError(w, http.StatusRequestEntityTooLarge, "too_many_events", "500 événements au plus par lot")
		return
	}

	now := s.now().UTC()
	resp := ingestResponse{Rejected: []rejection{}}
	valid := make([]*model.Event, 0, len(req.Events))
	for _, rawEv := range req.Events {
		ev, err := model.ParseEvent(rawEv, now)
		if err != nil {
			var ve *model.ValidationError
			if errors.As(err, &ve) {
				resp.Rejected = append(resp.Rejected, rejection{ID: ve.ID, Reason: ve.Reason})
				continue
			}
			resp.Rejected = append(resp.Rejected, rejection{Reason: model.ReasonInvalidJSON})
			continue
		}
		valid = append(valid, ev)
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
	defer cancel()
	res, err := s.st.Ingest(ctx, dev.DeviceID, cleanVersion(req.AgentVersion), valid, now)
	if err != nil {
		s.log.Error("ingestion : écriture en base impossible", "device_id", dev.DeviceID, "err", err)
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, "storage_error", "stockage momentanément indisponible")
		return
	}
	stored := res.Stored
	// An event older than the retention window is acknowledged ("accepted": the agent must not resend it)
	// but not stored: accepted + duplicates + rejected still totals the batch size.
	resp.Accepted = len(stored) + res.Expired
	resp.Duplicates = res.Duplicates
	resp.ServerTime = model.FormatTS(s.now())
	writeJSON(w, http.StatusOK, resp)

	if len(stored) > 0 {
		if s.exporter != nil {
			s.exporter.Notify()
		}
		s.broker.Publish(stored)
	}
	s.log.Debug("lot reçu", "device_id", dev.DeviceID, "accepted", resp.Accepted, "expired", res.Expired, "duplicates", res.Duplicates, "rejected", len(resp.Rejected))
	if len(resp.Rejected) > 0 {
		s.log.Warn("événements rejetés", "device_id", dev.DeviceID, "count", len(resp.Rejected), "first_reason", resp.Rejected[0].Reason)
	}
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.deviceAuth(w, r)
	if !ok {
		return
	}
	s.commitRenewal(r.Context(), dev)
	if err := s.st.TouchDevice(r.Context(), dev.DeviceID, "", s.now()); err != nil {
		s.log.Warn("ping : mise à jour de last_seen impossible", "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"server_time": model.FormatTS(s.now()), "device_id": dev.DeviceID})
}

// errTracker remembers the error of the wrapped reader, because decompressors
// may wrap it without supporting errors.As.
type errTracker struct {
	r   io.Reader
	err error
}

func (t *errTracker) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF {
		t.err = err
	}
	return n, err
}

func (t *errTracker) tooLarge() bool { return t.err != nil && tooLarge(t.err) }

func tooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

// cleanVersion keeps a short printable agent version, or "".
func cleanVersion(v string) string {
	if len(v) > 64 {
		return ""
	}
	for _, c := range v {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return v
}
