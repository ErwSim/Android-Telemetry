package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/model"
)

// Command statuses (contract §8).
const (
	CmdPending   = "pending"
	CmdDelivered = "delivered"
	CmdExecuted  = "executed"
	CmdFailed    = "failed"
	CmdRefused   = "refused"
	CmdExpired   = "expired"
	CmdCancelled = "cancelled"
)

// Command is one stored command.
type Command struct {
	ID          string
	DeviceID    string
	Type        string
	Params      json.RawMessage
	Payload     string // relayed byte for byte
	Sig         string // "" for a simple command
	Status      string
	CreatedMS   int64
	CreatedBy   string
	IssuedMS    int64
	ExpiresMS   int64
	DeliveredMS *int64
	Attempts    int
	ResultMS    *int64
	AgentAtMS   *int64
	Detail      string
}

// EffectiveStatus is the status shown to the console: an open command past its expiry is "expired"
// even before the background sweep has recorded it.
func (c *Command) EffectiveStatus(now time.Time) string {
	if (c.Status == CmdPending || c.Status == CmdDelivered) && c.ExpiresMS <= now.UnixMilli() {
		return CmdExpired
	}
	return c.Status
}

const commandCols = `id, device_id, type, params, payload, COALESCE(sig, ''), status, created_ms, created_by, issued_ms, expires_ms,
	delivered_ms, attempts, result_ms, agent_at_ms, COALESCE(detail, '')`

func scanCommand(sc interface{ Scan(...any) error }) (*Command, error) {
	var c Command
	var params string
	var delivered, result, agentAt sql.NullInt64
	if err := sc.Scan(&c.ID, &c.DeviceID, &c.Type, &params, &c.Payload, &c.Sig, &c.Status, &c.CreatedMS, &c.CreatedBy,
		&c.IssuedMS, &c.ExpiresMS, &delivered, &c.Attempts, &result, &agentAt, &c.Detail); err != nil {
		return nil, err
	}
	c.Params = json.RawMessage(params)
	c.DeliveredMS, c.ResultMS, c.AgentAtMS = nullInt(delivered), nullInt(result), nullInt(agentAt)
	return &c, nil
}

// SigErased replaces the signature of a signed command once the command can no longer be handed to the
// agent (result received, expired, cancelled). The collector cannot verify a signature and only needs it
// for the relay; kept longer, each (payload, signature) pair would stay in the database and in its backups
// as material for an offline search of the user's command passphrase. A real signature is 44 characters of
// base64, so the marker cannot be mistaken for one; "signed" stays true for the console.
const SigErased = "-"

const eraseSig = `sig = CASE WHEN sig IS NULL THEN NULL ELSE '` + SigErased + `' END`

// Command creation errors.
var (
	ErrDuplicateID = errors.New("command identifier already used")
	ErrConflict    = errors.New("incompatible state")
)

// LimitError is returned when a command limit is reached (contract §8: 429).
type LimitError struct {
	Msg        string
	RetryAfter time.Duration
}

func (e *LimitError) Error() string { return e.Msg }

// CommandLimits bounds the commands of one device.
type CommandLimits struct {
	PerHour    int // commands created during the last hour
	MaxPending int // open (pending or delivered) commands not expired
}

// NewCommand is a validated command to store.
type NewCommand struct {
	ID, DeviceID, Type string
	Params             json.RawMessage
	Payload, Sig       string
	CreatedBy          string
	IssuedMS           int64
	ExpiresMS          int64
	// Event is the data of the command.issued event recorded in the same transaction.
	Event    map[string]any
	EventSev int
}

// CreateCommand stores a command after checking, in the same write transaction (so that concurrent
// requests cannot exceed them), that the device exists and is not revoked, that the id is new, and the
// limits. The command.issued event is stored with it.
func (s *Store) CreateCommand(ctx context.Context, nc NewCommand, lim CommandLimits, now time.Time) (StoredEvent, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return StoredEvent{}, err
	}
	defer tx.Rollback()
	var revoked sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT revoked_ms FROM devices WHERE device_id = ?`, nc.DeviceID).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredEvent{}, ErrNotFound
	}
	if err != nil {
		return StoredEvent{}, err
	}
	if revoked.Valid {
		return StoredEvent{}, ErrRevoked
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM commands WHERE id = ?`, nc.ID).Scan(&exists); err != nil {
		return StoredEvent{}, err
	}
	if exists > 0 {
		return StoredEvent{}, ErrDuplicateID
	}
	nowMS := now.UnixMilli()
	var n int
	var oldest sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), MIN(created_ms) FROM commands INDEXED BY commands_dev_created
		WHERE device_id = ? AND created_ms > ?`, nc.DeviceID, nowMS-hourMS).Scan(&n, &oldest); err != nil {
		return StoredEvent{}, err
	}
	if n >= lim.PerHour {
		wait := time.Minute
		if oldest.Valid {
			wait = time.Duration(oldest.Int64+hourMS-nowMS) * time.Millisecond
		}
		return StoredEvent{}, &LimitError{Msg: fmt.Sprintf("%d commands per hour at most for this device", lim.PerHour), RetryAfter: wait}
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM commands INDEXED BY commands_open
		WHERE device_id = ? AND status IN ('pending', 'delivered') AND expires_ms > ?`, nc.DeviceID, nowMS).Scan(&n); err != nil {
		return StoredEvent{}, err
	}
	if n >= lim.MaxPending {
		return StoredEvent{}, &LimitError{Msg: fmt.Sprintf("%d pending commands at most for this device", lim.MaxPending), RetryAfter: time.Minute}
	}
	var sig any
	if nc.Sig != "" {
		sig = nc.Sig
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO commands(id, device_id, type, params, payload, sig, status, created_ms, created_by,
		issued_ms, expires_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, nc.ID, nc.DeviceID, nc.Type, string(nc.Params), nc.Payload, sig,
		CmdPending, nowMS, nc.CreatedBy, nc.IssuedMS, nc.ExpiresMS); err != nil {
		return StoredEvent{}, err
	}
	ev, err := insertServerEvent(ctx, tx, nc.DeviceID, "command.issued", nc.EventSev, nc.Event, now)
	if err != nil {
		return StoredEvent{}, err
	}
	return ev, tx.Commit()
}

// GetCommand returns one command.
func (s *Store) GetCommand(ctx context.Context, id string) (*Command, error) {
	c, err := scanCommand(s.r.QueryRowContext(ctx, `SELECT `+commandCols+` FROM commands WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// ListCommands returns the most recent commands (of one device when deviceID is set), newest first.
func (s *Store) ListCommands(ctx context.Context, deviceID string, limit int) ([]*Command, error) {
	q := `SELECT ` + commandCols + ` FROM commands`
	var args []any
	if deviceID != "" {
		q += ` INDEXED BY commands_dev_created WHERE device_id = ?`
		args = append(args, deviceID)
	}
	q += ` ORDER BY created_ms DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Command{}
	for rows.Next() {
		c, err := scanCommand(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CancelCommand cancels a command that is still pending (never handed to the agent) and records the
// command.cancelled event. It returns ErrNotFound for an unknown id and ErrConflict when the command is
// no longer pending (delivered, finished, expired or already cancelled).
func (s *Store) CancelCommand(ctx context.Context, id, user string, now time.Time) (StoredEvent, *Command, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return StoredEvent{}, nil, err
	}
	defer tx.Rollback()
	c, err := scanCommand(tx.QueryRowContext(ctx, `SELECT `+commandCols+` FROM commands WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return StoredEvent{}, nil, ErrNotFound
	}
	if err != nil {
		return StoredEvent{}, nil, err
	}
	nowMS := now.UnixMilli()
	res, err := tx.ExecContext(ctx, `UPDATE commands SET status = 'cancelled', result_ms = ?, detail = 'cancelled', `+eraseSig+`
		WHERE id = ? AND status = 'pending' AND expires_ms > ?`, nowMS, id, nowMS)
	if err != nil {
		return StoredEvent{}, nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return StoredEvent{}, c, ErrConflict
	}
	ev, err := insertServerEvent(ctx, tx, c.DeviceID, "command.cancelled", 0,
		map[string]any{"command_id": c.ID, "type": c.Type, "signed": c.Sig != "", "cancelled_by": user}, now)
	if err != nil {
		return StoredEvent{}, nil, err
	}
	c.Status = CmdCancelled
	return ev, c, tx.Commit()
}

// ClaimCommands marks as delivered, and returns, the commands to hand to the agent of a device: the
// pending ones not expired and, after redeliverAfter without a result, delivered ones again (at most
// maxAttempts deliveries; the agent refuses a command it already ran with "replay"). The transition
// happens before the command is written to the agent, so a concurrent cancellation either wins (the
// command is not sent) or fails with a conflict.
func (s *Store) ClaimCommands(ctx context.Context, deviceID string, now time.Time, redeliverAfter time.Duration, maxAttempts int) ([]*Command, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	nowMS := now.UnixMilli()
	rows, err := tx.QueryContext(ctx, `SELECT `+commandCols+` FROM commands INDEXED BY commands_open
		WHERE device_id = ? AND status IN ('pending', 'delivered') AND expires_ms > ? AND attempts < ?
		  AND (status = 'pending' OR delivered_ms <= ?)
		ORDER BY created_ms, id LIMIT 50`, deviceID, nowMS, maxAttempts, nowMS-redeliverAfter.Milliseconds())
	if err != nil {
		return nil, err
	}
	var out []*Command
	for rows.Next() {
		c, err := scanCommand(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, c := range out {
		if _, err := tx.ExecContext(ctx, `UPDATE commands SET status = 'delivered', delivered_ms = ?, attempts = attempts + 1
			WHERE id = ?`, nowMS, c.ID); err != nil {
			return nil, err
		}
		c.Status, c.DeliveredMS, c.Attempts = CmdDelivered, &nowMS, c.Attempts+1
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, tx.Commit()
}

// UnclaimCommand puts back a command whose writing to the agent failed, unless something else
// happened to it meanwhile (result received).
func (s *Store) UnclaimCommand(ctx context.Context, id string, claimMS int64) error {
	_, err := s.w.ExecContext(ctx, `UPDATE commands SET status = 'pending', delivered_ms = NULL, attempts = max(attempts - 1, 0)
		WHERE id = ? AND status = 'delivered' AND delivered_ms = ?`, id, claimMS)
	return err
}

// ResultUpdate describes a result reported by an agent.
type ResultUpdate struct {
	DeviceID, ID   string
	Status, Detail string
	AgentAtMS      *int64
	// Event builds the data and severity of the command.reported event from the stored command.
	Event func(c *Command) (map[string]any, int)
}

// RecordResult stores the result of a command of the device. The first final result wins (a
// duplicate is acknowledged without change); a "replay" refusal is not final (the agent already
// handled the command and reports its real result separately). It returns ErrNotFound when the
// command does not exist for this device, and the command.reported event when the status changed.
func (s *Store) RecordResult(ctx context.Context, u ResultUpdate, now time.Time) (*StoredEvent, *Command, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	c, err := scanCommand(tx.QueryRowContext(ctx, `SELECT `+commandCols+` FROM commands WHERE id = ? AND device_id = ?`, u.ID, u.DeviceID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	switch c.Status {
	case CmdExecuted, CmdFailed, CmdRefused:
		return nil, c, nil // idempotent: the first result is kept
	}
	if u.Status == CmdRefused && u.Detail == "replay" {
		return nil, c, nil
	}
	nowMS := now.UnixMilli()
	var agentAt any
	if u.AgentAtMS != nil {
		agentAt = *u.AgentAtMS
	}
	if _, err := tx.ExecContext(ctx, `UPDATE commands SET status = ?, detail = ?, result_ms = ?, agent_at_ms = ?, `+eraseSig+` WHERE id = ?`,
		u.Status, u.Detail, nowMS, agentAt, c.ID); err != nil {
		return nil, nil, err
	}
	c.Status, c.Detail, c.ResultMS, c.AgentAtMS = u.Status, u.Detail, &nowMS, u.AgentAtMS
	data, sev := u.Event(c)
	ev, err := insertServerEvent(ctx, tx, c.DeviceID, "command.reported", sev, data, now)
	if err != nil {
		return nil, nil, err
	}
	return &ev, c, tx.Commit()
}

// ExpireCommands records as expired the open commands past their expiry, with one command.expired
// event each.
func (s *Store) ExpireCommands(ctx context.Context, now time.Time, event func(c *Command) (map[string]any, int)) ([]StoredEvent, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	nowMS := now.UnixMilli()
	rows, err := tx.QueryContext(ctx, `SELECT `+commandCols+` FROM commands INDEXED BY commands_expiry
		WHERE status IN ('pending', 'delivered') AND expires_ms <= ? LIMIT 500`, nowMS)
	if err != nil {
		return nil, err
	}
	var cmds []*Command
	for rows.Next() {
		c, err := scanCommand(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		cmds = append(cmds, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(cmds) == 0 {
		return nil, err
	}
	var evs []StoredEvent
	for _, c := range cmds {
		if _, err := tx.ExecContext(ctx, `UPDATE commands SET status = 'expired', result_ms = ?, `+eraseSig+` WHERE id = ?`, nowMS, c.ID); err != nil {
			return nil, err
		}
		data, sev := event(c)
		ev, err := insertServerEvent(ctx, tx, c.DeviceID, "command.expired", sev, data, now)
		if err != nil {
			return nil, err
		}
		evs = append(evs, ev)
	}
	return evs, tx.Commit()
}

// Command channel modes (GET /devices, command_channel.mode).
const (
	ChannelStream = "stream"
	ChannelPoll   = "poll"
)

// TouchCommandChannel records the last contact of a device on the command channel ("" keeps the mode).
func (s *Store) TouchCommandChannel(ctx context.Context, deviceID, mode string, now time.Time) error {
	_, err := s.w.ExecContext(ctx, `UPDATE devices SET cmd_mode = COALESCE(NULLIF(?, ''), cmd_mode), cmd_contact_ms = ? WHERE device_id = ?`,
		mode, now.UnixMilli(), deviceID)
	return err
}

// insertServerEvent stores an event produced by the collector itself (source "server") in the
// caller's transaction, with its derived rows (hourly counts, type list).
func insertServerEvent(ctx context.Context, tx *sql.Tx, deviceID, typ string, sev int, data map[string]any, now time.Time) (StoredEvent, error) {
	if data == nil {
		data = map[string]any{}
	}
	raw, err := model.Marshal(data)
	if err != nil {
		return StoredEvent{}, err
	}
	nowMS := now.UnixMilli()
	id := model.NewULID(now)
	r, err := tx.ExecContext(ctx, `INSERT INTO events(id, device_id, ts_ms, received_ms, seq, boot_id, elapsed_ms, type, sev, data, source)
		VALUES(?,?,?,?,0,'server',0,?,?,?,'server')`, id, deviceID, nowMS, nowMS, typ, sev, string(raw))
	if err != nil {
		return StoredEvent{}, err
	}
	pk, err := r.LastInsertId()
	if err != nil {
		return StoredEvent{}, err
	}
	hour := nowMS - mod(nowMS, hourMS)
	if _, err := tx.ExecContext(ctx, `INSERT INTO event_counts(hour_ms, device_id, type, sev, count) VALUES(?,?,?,?,1)
		ON CONFLICT(hour_ms, device_id, type, sev) DO UPDATE SET count = count + 1`, hour, deviceID, typ, sev); err != nil {
		return StoredEvent{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO event_types(device_id, type) VALUES(?, ?)`, deviceID, typ); err != nil {
		return StoredEvent{}, err
	}
	return StoredEvent{PK: pk, ID: id, DeviceID: deviceID, TSms: nowMS, ReceivedMS: nowMS, BootID: "server",
		Type: typ, Sev: sev, Data: raw, Source: "server"}, nil
}

// AddServerEvents stores one event produced by the collector (source "server") for every device that is
// not revoked, in one transaction: an action that concerns the whole installation rather than one device
// (a change made in AdGuard Home from the console) appears in the timeline of each device and is exported
// once per device. It returns nothing when no device is enrolled.
func (s *Store) AddServerEvents(ctx context.Context, typ string, sev int, data map[string]any, now time.Time) ([]StoredEvent, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT device_id FROM devices WHERE revoked_ms IS NULL ORDER BY device_id`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(ids) == 0 {
		return nil, err
	}
	out := make([]StoredEvent, 0, len(ids))
	for _, id := range ids {
		ev, err := insertServerEvent(ctx, tx, id, typ, sev, data, now)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, tx.Commit()
}

// CommandChannelState is the stored command channel state of a device.
type CommandChannelState struct {
	Mode      string
	ContactMS *int64
}

// CommandChannels returns the stored command channel state of every device.
func (s *Store) CommandChannels(ctx context.Context) (map[string]CommandChannelState, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT device_id, COALESCE(cmd_mode, ''), cmd_contact_ms FROM devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]CommandChannelState{}
	for rows.Next() {
		var id, mode string
		var contact sql.NullInt64
		if err := rows.Scan(&id, &mode, &contact); err != nil {
			return nil, err
		}
		out[id] = CommandChannelState{Mode: strings.TrimSpace(mode), ContactMS: nullInt(contact)}
	}
	return out, rows.Err()
}
