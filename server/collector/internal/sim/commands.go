package sim

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/command"
)

// AgentCommand is a command object received from the collector (contract §8).
type AgentCommand struct {
	ID      string `json:"id"`
	Payload string `json:"payload"`
	Sig     string `json:"sig,omitempty"`
}

// PollCommands calls GET /api/v1/commands.
func (c *Client) PollCommands(ctx context.Context) ([]AgentCommand, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/v1/commands", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("commandes : HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var r struct {
		Commands []AgentCommand `json:"commands"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return r.Commands, nil
}

// StreamCommands opens GET /api/v1/commands/stream and calls fn for every command until the stream
// ends (error, server closing it, ctx canceled).
func (c *Client) StreamCommands(ctx context.Context, fn func(AgentCommand)) error {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/v1/commands/stream", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	stream := &http.Client{Transport: c.http.Transport} // no global timeout: long-lived response
	resp, err := stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("flux de commandes : HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	// A dead connection is detected by the missing keep-alive comments.
	alive := make(chan struct{}, 1)
	go func() {
		t := time.NewTimer(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-alive:
				if !ok {
					return
				}
				t.Reset(5 * time.Minute)
			case <-t.C:
				resp.Body.Close()
				return
			}
		}
	}()
	defer close(alive)
	rd := bufio.NewReaderSize(resp.Body, 64<<10)
	var event, data string
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("flux de commandes fermé : %w", err)
		}
		select {
		case alive <- struct{}{}:
		default:
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			if event == "command" && data != "" {
				var cmd AgentCommand
				if json.Unmarshal([]byte(data), &cmd) == nil {
					fn(cmd)
				}
			}
			event, data = "", ""
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data += strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
		}
	}
}

// PostResult calls POST /api/v1/commands/{id}/result, retrying on network errors, 429 and 5xx.
func (c *Client) PostResult(ctx context.Context, id, status, detail string, at time.Time) error {
	body, _ := json.Marshal(map[string]string{"status": status, "detail": detail, "at": at.UTC().Format("2006-01-02T15:04:05.000Z07:00")})
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		req, err := c.newRequest(ctx, http.MethodPost, "/api/v1/commands/"+id+"/result", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent {
				return nil
			}
			last = fmt.Errorf("résultat : HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return last
			}
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * time.Second):
		}
	}
	return last
}

// AgentOptions configure the simulated command handling of the agent.
type AgentOptions struct {
	DeviceID  string
	Code      string        // command code ("" : no code configured, sensitive commands refused)
	AllowWipe bool          // "Autoriser l'effacement à distance" (off by default, as in the app)
	ClockSkew time.Duration // offset of the phone clock (to provoke "expired" refusals)
	Log       io.Writer
}

// Injection is an event or action the simulated agent asks the simulation loop to add.
type Injection struct {
	At     time.Time
	Locate bool // emit an immediate precise location.fix
	Type   string
	Sev    int
	Data   map[string]any
}

// CommandAgent applies the checks of contract §8 (same order, same refusal reasons) and "executes"
// commands virtually.
type CommandAgent struct {
	opts   AgentOptions
	key    []byte
	client *Client
	out    chan<- Injection

	mu     sync.Mutex
	seen   []string // last 500 executed ids
	badSig []time.Time
}

// NewCommandAgent derives the key from the code (PBKDF2, 600 000 iterations) once.
func NewCommandAgent(c *Client, opts AgentOptions, out chan<- Injection) (*CommandAgent, error) {
	a := &CommandAgent{opts: opts, client: c, out: out}
	if opts.Log == nil {
		a.opts.Log = io.Discard
	}
	if opts.Code != "" {
		if len([]rune(opts.Code)) < 12 {
			return nil, errors.New("--command-code : 12 caractères au moins (contrat §8)")
		}
		k, err := command.DeriveKey(opts.Code, opts.DeviceID)
		if err != nil {
			return nil, err
		}
		a.key = k
	}
	return a, nil
}

func (a *CommandAgent) now() time.Time { return time.Now().Add(a.opts.ClockSkew) }

// Check returns the outcome of the checks of contract §8, in order: "" when the command may run,
// otherwise the refusal reason.
func (a *CommandAgent) Check(cmd AgentCommand) (typ, reason string) {
	var p struct {
		V         json.RawMessage `json:"v"`
		ID        string          `json:"id"`
		DeviceID  string          `json:"device_id"`
		Type      string          `json:"type"`
		IssuedAt  string          `json:"issued_at"`
		ExpiresAt string          `json:"expires_at"`
	}
	if json.Unmarshal([]byte(cmd.Payload), &p) != nil || string(p.V) != "1" || p.ID != cmd.ID {
		return "", "malformed"
	}
	if p.DeviceID != a.opts.DeviceID {
		return p.Type, "wrong_device"
	}
	if !command.Known(p.Type) {
		return p.Type, "unknown_type"
	}
	now := a.now()
	if command.Sensitive(p.Type) {
		if a.key == nil {
			return p.Type, "no_code_configured"
		}
		a.mu.Lock()
		var recent []time.Time
		for _, t := range a.badSig {
			if now.Sub(t) < time.Hour {
				recent = append(recent, t)
			}
		}
		a.badSig = recent
		locked := len(recent) >= 5
		a.mu.Unlock()
		if locked {
			return p.Type, "locked_out"
		}
		if !command.Verify(a.key, cmd.Payload, cmd.Sig) {
			a.mu.Lock()
			a.badSig = append(a.badSig, now)
			a.mu.Unlock()
			return p.Type, "bad_signature"
		}
		if p.Type == command.TypeWipe && !a.opts.AllowWipe {
			return p.Type, "disabled"
		}
	}
	exp, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil {
		return p.Type, "malformed"
	}
	if now.After(exp.Add(5 * time.Minute)) {
		return p.Type, "expired"
	}
	// Validity bounds checked by the agent (contract §8): 30 days at most, 24 hours for wipe.
	if iss, err := time.Parse(time.RFC3339Nano, p.IssuedAt); err == nil {
		if v := exp.Sub(iss); v > command.MaxValidity || (p.Type == command.TypeWipe && v > command.MaxWipeValidity) {
			return p.Type, "expired"
		}
	}
	a.mu.Lock()
	for _, id := range a.seen {
		if id == cmd.ID {
			a.mu.Unlock()
			return p.Type, "replay"
		}
	}
	a.mu.Unlock()
	if _, err := command.Parse(cmd.Payload); err != nil {
		return p.Type, "bad_params"
	}
	return p.Type, "" // the simulated agent is Device Owner: no not_device_owner refusal
}

// Handle checks, "executes" and reports one command: POST of the result and command.result event.
func (a *CommandAgent) Handle(ctx context.Context, cmd AgentCommand) {
	typ, reason := a.Check(cmd)
	status, detail := command.StatusExecuted, ""
	now := time.Now()
	if reason != "" {
		status, detail = command.StatusRefused, reason
		fmt.Fprintf(a.opts.Log, "\ncommande %s (%s) refusée : %s\n", cmd.ID, typ, reason)
	} else {
		p, _ := command.Parse(cmd.Payload)
		detail = a.execute(p, now)
		a.mu.Lock()
		a.seen = append(a.seen, cmd.ID)
		if len(a.seen) > 500 {
			a.seen = a.seen[len(a.seen)-500:]
		}
		a.mu.Unlock()
	}
	data := map[string]any{"command_id": cmd.ID, "type": typ, "status": status, "signed": cmd.Sig != ""}
	if detail != "" {
		data["detail"] = detail
	}
	a.out <- Injection{At: now, Type: "command.result", Sev: command.ResultSeverity(typ, status, detail), Data: data}
	if err := a.client.PostResult(ctx, cmd.ID, status, detail, now); err != nil {
		fmt.Fprintf(a.opts.Log, "\nrésultat de %s non transmis : %v\n", cmd.ID, err)
	}
}

func (a *CommandAgent) execute(p *command.Payload, now time.Time) string {
	w := a.opts.Log
	switch p.Type {
	case command.TypeRing:
		d, _ := p.Params["duration_s"].(int64)
		if d == 0 {
			d = 60
		}
		fmt.Fprintf(w, "\n[simulé] sonnerie à plein volume pendant %d s (commande %s)\n", d, p.ID)
	case command.TypeVibrate:
		fmt.Fprintf(w, "\n[simulé] vibration (commande %s)\n", p.ID)
	case command.TypeStopRing:
		fmt.Fprintf(w, "\n[simulé] arrêt de la sonnerie (commande %s)\n", p.ID)
	case command.TypeLocate:
		fmt.Fprintf(w, "\n[simulé] position précise demandée (commande %s)\n", p.ID)
		a.out <- Injection{At: now, Locate: true}
	case command.TypeLock:
		msg, _ := p.Params["message"].(string)
		fmt.Fprintf(w, "\n[simulé] verrouillage, message affiché : %q (commande %s)\n", msg, p.ID)
	case command.TypeClearLockMessage:
		fmt.Fprintf(w, "\n[simulé] message d'écran de verrouillage effacé (commande %s)\n", p.ID)
	case command.TypeWipe:
		fmt.Fprintf(w, "\n[simulé] RÉINITIALISATION D'USINE (simulée : rien n'est effacé) (commande %s)\n", p.ID)
	}
	return ""
}

// RunStream keeps a command stream open, reconnecting with backoff.
func (a *CommandAgent) RunStream(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.client.StreamCommands(ctx, func(cmd AgentCommand) { a.Handle(ctx, cmd) })
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		fmt.Fprintf(a.opts.Log, "\nflux de commandes interrompu (%v), reconnexion dans %s\n", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// RunPoll polls for commands every interval.
func (a *CommandAgent) RunPoll(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if cmds, err := a.client.PollCommands(ctx); err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(a.opts.Log, "\ninterrogation des commandes en échec : %v\n", err)
			}
		} else {
			for _, c := range cmds {
				a.Handle(ctx, c)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
