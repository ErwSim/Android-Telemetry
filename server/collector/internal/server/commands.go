package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/erwsim/watchpost/server/collector/internal/command"
	"github.com/erwsim/watchpost/server/collector/internal/model"
	"github.com/erwsim/watchpost/server/collector/internal/store"
)

// Remote commands (contract §8). The collector relays commands of a closed list to the agent; the
// payload string is stored and relayed byte for byte, and the signature of a sensitive command (which
// the collector cannot verify: it never knows the command code) is only required to be present.

const (
	cmdPerHour        = 20
	cmdMaxPending     = 10
	cmdMaxStreams     = 64              // command streams open at once (one per device)
	cmdRedeliverAfter = 5 * time.Minute // a delivered command without result is sent again after this
	cmdMaxAttempts    = 3
	cmdWriteTimeout   = 30 * time.Second
	cmdMaxBody        = 32 << 10
	cmdMaxResultBody  = 4 << 10
	cmdMaxDetail      = 200
	cmdExpirySweep    = 30 * time.Second
)

// cmdHub tracks the command stream of each device: one connection per device, a new one replacing
// the previous (contract §8), and wakes it up when a command is created.
type cmdHub struct {
	mu     sync.Mutex
	conns  map[string]*cmdConn
	max    int
	closed bool
}

type cmdConn struct {
	device string
	wake   chan struct{} // buffered (1): a command is waiting
	done   chan struct{} // closed when replaced or at shutdown
	once   sync.Once
}

func (c *cmdConn) stop() { c.once.Do(func() { close(c.done) }) }

func newCmdHub(max int) *cmdHub { return &cmdHub{conns: map[string]*cmdConn{}, max: max} }

var errTooManyStreams = errors.New("trop de flux de commandes ouverts")

// attach registers the stream of a device, closing the previous one.
func (h *cmdHub) attach(device string) (*cmdConn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, errTooManyStreams
	}
	old := h.conns[device]
	if old == nil && len(h.conns) >= h.max {
		return nil, errTooManyStreams
	}
	if old != nil {
		old.stop()
	}
	c := &cmdConn{device: device, wake: make(chan struct{}, 1), done: make(chan struct{})}
	h.conns[device] = c
	return c, nil
}

// detach forgets c unless it was already replaced.
func (h *cmdHub) detach(c *cmdConn) {
	h.mu.Lock()
	if h.conns[c.device] == c {
		delete(h.conns, c.device)
	}
	h.mu.Unlock()
	c.stop()
}

func (h *cmdHub) notify(device string) {
	h.mu.Lock()
	c := h.conns[device]
	h.mu.Unlock()
	if c != nil {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
}

func (h *cmdHub) connected(device string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[device] != nil
}

func (h *cmdHub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for d, c := range h.conns {
		delete(h.conns, d)
		c.stop()
	}
}

// agentCommand is the command object sent to the agent.
type agentCommand struct {
	ID      string `json:"id"`
	Payload string `json:"payload"`
	Sig     string `json:"sig,omitempty"`
}

func toAgent(c *store.Command) agentCommand {
	return agentCommand{ID: c.ID, Payload: c.Payload, Sig: c.Sig}
}

// --- agent side (/api/v1, same authentication as ingestion) -----------------------------------

func (s *Server) handleCommandStream(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.deviceAuth(w, r)
	if !ok {
		return
	}
	s.commitRenewal(r.Context(), dev)
	conn, err := s.cmdHub.attach(dev.DeviceID)
	if err != nil {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, "too_many_streams", err.Error())
		return
	}
	defer s.cmdHub.detach(conn)
	ctx := r.Context()
	s.touchChannel(dev.DeviceID, store.ChannelStream)
	defer s.touchChannel(dev.DeviceID, store.ChannelStream)
	s.log.Info("flux de commandes ouvert", "device_id", dev.DeviceID)
	defer s.log.Info("flux de commandes fermé", "device_id", dev.DeviceID)

	rc := http.NewResponseController(w)
	// The server-wide read timeout would end this long-lived request; writes keep a deadline each.
	_ = rc.SetReadDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	write := func(p []byte) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(cmdWriteTimeout))
		if _, err := w.Write(p); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !write([]byte("retry: 10000\n: ok\n\n")) {
		return
	}
	deliver := func() bool {
		cmds, err := s.st.ClaimCommands(ctx, dev.DeviceID, s.now(), cmdRedeliverAfter, cmdMaxAttempts)
		if err != nil {
			if ctx.Err() == nil {
				s.log.Error("commandes : lecture des commandes en attente impossible", "device_id", dev.DeviceID, "err", err)
			}
			return ctx.Err() == nil
		}
		for i, c := range cmds {
			b, err := model.Marshal(toAgent(c))
			if err != nil {
				continue
			}
			msg := make([]byte, 0, len(b)+32)
			msg = append(msg, "event: command\ndata: "...)
			msg = append(msg, b...)
			msg = append(msg, "\n\n"...)
			if !write(msg) {
				// Not handed over: back to pending for the next connection (or a poll).
				bg := context.WithoutCancel(ctx)
				for _, u := range cmds[i:] {
					if err := s.st.UnclaimCommand(bg, u.ID, *u.DeliveredMS); err != nil {
						s.log.Warn("commandes : remise en attente impossible", "command_id", u.ID, "err", err)
					}
				}
				return false
			}
			s.log.Info("commande remise à l'agent", "command_id", c.ID, "device_id", c.DeviceID, "type", c.Type, "mode", "stream", "attempt", c.Attempts)
		}
		return true
	}
	if !deliver() {
		return
	}
	ticker := time.NewTicker(s.cfg.CmdKeepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-conn.done: // replaced by a newer connection of the same device, or shutdown
			return
		case <-conn.wake:
			if !deliver() {
				return
			}
		case <-ticker.C:
			// A revocation or a renewal switchover made meanwhile ends the stream.
			if cur, err := s.authenticateDevice(r); err != nil || cur.DeviceID != dev.DeviceID {
				if errors.Is(err, errUnauthorized) {
					s.log.Info("flux de commandes : identifiants plus valides, fermeture", "device_id", dev.DeviceID)
					return
				}
				if err != nil && ctx.Err() == nil {
					s.log.Warn("flux de commandes : vérification des identifiants impossible", "device_id", dev.DeviceID, "err", err)
				}
			}
			if !write([]byte(": ka\n\n")) {
				return
			}
			s.touchChannel(dev.DeviceID, "")
			if !deliver() {
				return
			}
		}
	}
}

func (s *Server) touchChannel(device, mode string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.st.TouchCommandChannel(ctx, device, mode, s.now()); err != nil {
		s.log.Warn("commandes : mise à jour du canal impossible", "device_id", device, "err", err)
	}
}

func (s *Server) handleCommandPoll(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.deviceAuth(w, r)
	if !ok {
		return
	}
	s.commitRenewal(r.Context(), dev)
	mode := store.ChannelPoll
	if s.cmdHub.connected(dev.DeviceID) {
		mode = "" // the agent also polls at each upload while its stream is open
	}
	s.touchChannel(dev.DeviceID, mode)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	cmds, err := s.st.ClaimCommands(ctx, dev.DeviceID, s.now(), cmdRedeliverAfter, cmdMaxAttempts)
	if err != nil {
		s.log.Error("commandes : lecture des commandes en attente impossible", "device_id", dev.DeviceID, "err", err)
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, "unavailable", "service momentanément indisponible")
		return
	}
	out := make([]agentCommand, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, toAgent(c))
		s.log.Info("commande remise à l'agent", "command_id", c.ID, "device_id", c.DeviceID, "type", c.Type, "mode", "poll", "attempt", c.Attempts)
	}
	writeJSON(w, http.StatusOK, map[string]any{"commands": out})
}

type resultRequest struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
	At     string `json:"at"`
}

func (s *Server) handleCommandResult(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.deviceAuth(w, r)
	if !ok {
		return
	}
	s.commitRenewal(r.Context(), dev)
	id := r.PathValue("id")
	if !model.ValidULID(id) {
		writeError(w, http.StatusNotFound, "not_found", "commande introuvable")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cmdMaxResultBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "4 Kio au plus")
		return
	}
	var req resultRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "JSON { status, detail, at } attendu")
		return
	}
	if !command.ValidResultStatus(req.Status) {
		writeError(w, http.StatusBadRequest, "invalid_status", "status : executed, failed ou refused")
		return
	}
	req.Detail = strings.TrimSpace(req.Detail)
	if len(req.Detail) > cmdMaxDetail || strings.IndexFunc(req.Detail, unicode.IsControl) >= 0 {
		writeError(w, http.StatusBadRequest, "invalid_detail", "detail : 200 octets imprimables au plus")
		return
	}
	var atMS *int64
	if req.At != "" {
		t, err := time.Parse(time.RFC3339Nano, req.At)
		if err != nil || len(req.At) > 40 {
			writeError(w, http.StatusBadRequest, "invalid_at", "at : date RFC 3339 attendue")
			return
		}
		ms := t.UnixMilli()
		atMS = &ms
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	ev, c, err := s.st.RecordResult(ctx, store.ResultUpdate{
		DeviceID: dev.DeviceID, ID: id, Status: req.Status, Detail: req.Detail, AgentAtMS: atMS,
		Event: func(c *store.Command) (map[string]any, int) {
			d := map[string]any{"command_id": c.ID, "type": c.Type, "status": req.Status, "signed": c.Sig != ""}
			if req.Detail != "" {
				d["detail"] = req.Detail
			}
			if atMS != nil {
				d["agent_at"] = model.FormatMS(*atMS)
			}
			return d, command.ResultSeverity(c.Type, req.Status, req.Detail)
		},
	}, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "commande introuvable")
		return
	case err != nil:
		s.log.Error("commandes : enregistrement du résultat impossible", "command_id", id, "err", err)
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, "unavailable", "service momentanément indisponible")
		return
	}
	s.touchChannel(dev.DeviceID, "")
	if ev != nil {
		s.log.Info("résultat de commande", "command_id", c.ID, "device_id", c.DeviceID, "type", c.Type, "status", c.Status, "detail", c.Detail)
		s.published([]store.StoredEvent{*ev})
	} else {
		s.log.Info("résultat de commande sans effet (doublon ou rejeu)", "command_id", id, "device_id", dev.DeviceID,
			"current_status", c.Status, "reported_status", req.Status, "detail", req.Detail)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// published hands events produced by the collector to the exporter and the console stream.
func (s *Server) published(evs []store.StoredEvent) {
	if len(evs) == 0 {
		return
	}
	if s.exporter != nil {
		s.exporter.Notify()
	}
	s.broker.Publish(evs)
}

// --- console side -------------------------------------------------------------------------------

// consoleCommand is one entry of GET /api/console/commands.
type consoleCommand struct {
	ID          string          `json:"id"`
	DeviceID    string          `json:"device_id"`
	Type        string          `json:"type"`
	Params      json.RawMessage `json:"params"`
	Signed      bool            `json:"signed"`
	Status      string          `json:"status"`
	CreatedAt   string          `json:"created_at"`
	CreatedBy   string          `json:"created_by"`
	ExpiresAt   string          `json:"expires_at"`
	DeliveredAt *string         `json:"delivered_at,omitempty"`
	ResultAt    *string         `json:"result_at,omitempty"`
	Detail      *string         `json:"detail,omitempty"`
}

func fmtPtr(ms *int64) *string {
	if ms == nil {
		return nil
	}
	v := model.FormatMS(*ms)
	return &v
}

func (s *Server) handleListCommands(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	dev, err := deviceParam(v, false)
	if err != nil {
		s.fail(w, err)
		return
	}
	limit, err := intParam(v, "limit", 50, 1, 500)
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	cmds, err := s.st.ListCommands(ctx, dev, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	now := s.now()
	out := make([]consoleCommand, 0, len(cmds))
	for _, c := range cmds {
		cc := consoleCommand{
			ID: c.ID, DeviceID: c.DeviceID, Type: c.Type, Params: c.Params, Signed: c.Sig != "", Status: c.EffectiveStatus(now),
			CreatedAt: model.FormatMS(c.CreatedMS), CreatedBy: c.CreatedBy, ExpiresAt: model.FormatMS(c.ExpiresMS),
			DeliveredAt: fmtPtr(c.DeliveredMS), ResultAt: fmtPtr(c.ResultMS),
		}
		if c.Detail != "" {
			d := c.Detail
			cc.Detail = &d
		}
		out = append(out, cc)
	}
	writeJSON(w, http.StatusOK, map[string]any{"commands": out})
}

func (s *Server) handleCreateCommand(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userKey).(string)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cmdMaxBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "requête trop volumineuse")
		return
	}
	fields, err := command.StrictObject(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "JSON { device_id, payload, sig } attendu : "+err.Error())
		return
	}
	str := func(k string, required bool) (string, bool) {
		raw, ok := fields[k]
		if !ok || string(raw) == "null" {
			return "", !required
		}
		var v string
		if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &v) != nil {
			return "", false
		}
		return v, true
	}
	for k := range fields {
		if k != "device_id" && k != "payload" && k != "sig" && k != "id" {
			writeError(w, http.StatusBadRequest, "invalid_json", "champ inconnu : "+k)
			return
		}
	}
	deviceID, ok1 := str("device_id", true)
	payload, ok2 := str("payload", true)
	sig, ok3 := str("sig", false)
	bodyID, ok4 := str("id", false)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		writeError(w, http.StatusBadRequest, "invalid_json", "device_id et payload (chaînes) requis ; sig et id : chaînes")
		return
	}
	if !validDeviceID(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid_parameter", "device_id invalide")
		return
	}
	p, err := command.Parse(payload)
	if err != nil {
		var ce *command.Error
		if errors.As(err, &ce) {
			writeError(w, http.StatusBadRequest, ce.Code, ce.Msg)
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_payload", "payload invalide")
		return
	}
	now := s.now()
	switch {
	case p.DeviceID != deviceID:
		writeError(w, http.StatusBadRequest, "wrong_device", "device_id du payload différent de celui de la requête")
		return
	case bodyID != "" && bodyID != p.ID:
		writeError(w, http.StatusBadRequest, "invalid_payload", "id différent de celui du payload")
		return
	case command.Sensitive(p.Type) && sig == "":
		writeError(w, http.StatusBadRequest, "signature_required", "commande sensible : signature (sig) requise")
		return
	case command.Sensitive(p.Type) && !command.ValidSignatureFormat(sig):
		writeError(w, http.StatusBadRequest, "invalid_signature", "sig : base64 de 32 octets (HMAC-SHA256) attendu")
		return
	case !command.Sensitive(p.Type) && sig != "":
		writeError(w, http.StatusBadRequest, "signature_not_allowed", "commande simple : pas de signature")
		return
	}
	if err := p.CheckTime(now); err != nil {
		var ce *command.Error
		errors.As(err, &ce)
		writeError(w, http.StatusBadRequest, ce.Code, ce.Msg)
		return
	}
	params, err := model.Marshal(p.Params)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_params", "paramètres illisibles")
		return
	}
	// The lock message is the owner's data: kept in the database for the console, not copied
	// into the exported event (nor into the process logs).
	evParams := map[string]any{}
	for k, v := range p.Params {
		if k != "message" {
			evParams[k] = v
		}
	}
	evData := map[string]any{"command_id": p.ID, "type": p.Type, "signed": sig != "", "created_by": user,
		"expires_at": model.FormatTS(p.ExpiresAt), "params": evParams}
	if p.Type == command.TypeLock {
		msg, _ := p.Params["message"].(string)
		evData["message_set"] = msg != ""
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	ev, err := s.st.CreateCommand(ctx, store.NewCommand{
		ID: p.ID, DeviceID: deviceID, Type: p.Type, Params: params, Payload: payload, Sig: sig, CreatedBy: user,
		IssuedMS: p.IssuedAt.UnixMilli(), ExpiresMS: p.ExpiresAt.UnixMilli(), Event: evData, EventSev: command.IssuedSeverity(p.Type),
	}, store.CommandLimits{PerHour: cmdPerHour, MaxPending: cmdMaxPending}, now)
	var le *store.LimitError
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "appareil inconnu")
		return
	case errors.Is(err, store.ErrRevoked):
		writeError(w, http.StatusConflict, "device_revoked", "appareil révoqué")
		return
	case errors.Is(err, store.ErrDuplicateID):
		writeError(w, http.StatusConflict, "duplicate_id", "identifiant de commande déjà utilisé")
		return
	case errors.As(err, &le):
		writeRetry(w, le.RetryAfter, le.Msg)
		return
	case err != nil:
		s.log.Error("commandes : création impossible", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "service momentanément indisponible")
		return
	}
	s.log.Info("commande émise", "command_id", p.ID, "device_id", deviceID, "type", p.Type, "signed", sig != "",
		"user", user, "expires_at", model.FormatTS(p.ExpiresAt))
	s.published([]store.StoredEvent{ev})
	s.cmdHub.notify(deviceID)
	writeJSON(w, http.StatusCreated, map[string]string{"id": p.ID})
}

func (s *Server) handleCancelCommand(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userKey).(string)
	id := r.PathValue("id")
	if !model.ValidULID(id) {
		writeError(w, http.StatusNotFound, "not_found", "commande introuvable")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	ev, c, err := s.st.CancelCommand(ctx, id, user, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "commande introuvable")
		return
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "not_pending", "commande déjà remise à l'appareil, terminée, expirée ou annulée (statut : "+c.EffectiveStatus(s.now())+")")
		return
	case err != nil:
		s.log.Error("commandes : annulation impossible", "command_id", id, "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "service momentanément indisponible")
		return
	}
	s.log.Info("commande annulée", "command_id", id, "device_id", c.DeviceID, "type", c.Type, "user", user)
	s.published([]store.StoredEvent{ev})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// RunCommands records expired commands until ctx is canceled.
func (s *Server) RunCommands(ctx context.Context) {
	t := time.NewTicker(cmdExpirySweep)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.expireCommands(ctx)
	}
}

func (s *Server) expireCommands(ctx context.Context) {
	for range 20 { // 500 per round
		evs, err := s.st.ExpireCommands(ctx, s.now(), func(c *store.Command) (map[string]any, int) {
			return map[string]any{"command_id": c.ID, "type": c.Type, "signed": c.Sig != "", "delivered": c.Status == store.CmdDelivered}, 1
		})
		if err != nil {
			if ctx.Err() == nil {
				s.log.Error("commandes : expiration impossible", "err", err)
			}
			return
		}
		for _, ev := range evs {
			var d map[string]any
			_ = json.Unmarshal(ev.Data, &d)
			s.log.Info("commande expirée sans résultat", "command_id", d["command_id"], "device_id", ev.DeviceID, "type", d["type"])
		}
		s.published(evs)
		if len(evs) < 500 {
			return
		}
	}
}

// CloseStreams ends the console event streams and the agents' command streams (shutdown).
func (s *Server) CloseStreams() {
	s.broker.Close()
	s.cmdHub.close()
}
