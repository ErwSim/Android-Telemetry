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

// Storage side of the behavioral detections (contract §11.3): the aggregates they read (ops_counts,
// app_latest, tracking_counts.threat, plus the existing usage_counts and top_counts), the hours to evaluate
// again (detect_dirty) and the detections themselves. Nothing here scans the events table: the detections
// read hourly aggregates and, for the rare application events, the (device_id, type, ts_ms) index.

// DetectionInput reports whether events of type t feed a detection: storing one marks its hour (UTC, of its
// ts) to be evaluated again, so that a late batch, even days late, is looked at.
func DetectionInput(t string) bool {
	switch t {
	case "net.dns", "net.connect", "net.usage", "app.ops", "app.risk", "app.installed", "app.permission_changed",
		"app.special_access", "app.role", "app.inventory":
		return true
	}
	return false
}

// Kinds of app_latest.
const (
	AppLatestRisk = "risk" // key: package, data: latest app.risk
	AppLatestRole = "role" // key: role, data: latest app.role
)

type appKey struct{ kind, key string }

func appLatestKey(ev *model.Event) (appKey, bool) {
	var kind, field string
	switch ev.Type {
	case "app.risk":
		kind, field = AppLatestRisk, "package"
	case "app.role":
		kind, field = AppLatestRole, "role"
	default:
		return appKey{}, false
	}
	k, _ := model.Str(ev.Decoded, field)
	if k == "" {
		return appKey{}, false
	}
	return appKey{kind: kind, key: clip(k, maxKeyLen)}, true
}

type opsKey struct {
	hour    int64
	pkg, op string
}

type opsVal struct{ count, bg, rej, last int64 }

// maxOpCount bounds one count of app.ops (a hostile value can neither wrap around nor dominate).
const maxOpCount = 1_000_000_000

// addOps accumulates the elements {package, op, count, background_count, last_ts} of an app.ops event.
func addOps(acc map[opsKey]*opsVal, hour int64, d map[string]any) {
	list, _ := d["apps"].([]any)
	for _, a := range list {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		p, _ := model.Str(m, "package")
		op, _ := model.Str(m, "op")
		if p == "" || op == "" {
			continue
		}
		c, _ := model.Int(m, "count")
		b, _ := model.Int(m, "background_count")
		r, _ := model.Int(m, "rejected_count")
		k := opsKey{hour: hour, pkg: clip(p, maxKeyLen), op: clip(op, 32)}
		v := acc[k]
		if v == nil {
			v = &opsVal{}
			acc[k] = v
		}
		v.count = min(v.count+min(max(c, 0), maxOpCount), maxCountedBytes)
		v.bg = min(v.bg+min(max(b, 0), maxOpCount), maxCountedBytes)
		v.rej = min(v.rej+min(max(r, 0), maxOpCount), maxCountedBytes)
		if s, ok := model.Str(m, "last_ts"); ok {
			if t, err := time.Parse(time.RFC3339Nano, s); err == nil && t.UnixMilli() > v.last {
				v.last = t.UnixMilli()
			}
		}
	}
}

func writeDetectInputs(ctx context.Context, tx *sql.Tx, deviceID string, ops map[opsKey]*opsVal, apps map[appKey]StoredEvent, dirty map[int64]bool) error {
	for k, v := range ops {
		var last any
		if v.last > 0 {
			last = v.last
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ops_counts(device_id, hour_ms, package, op, count, bg_count, rej_count, last_ms) VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(device_id, hour_ms, package, op) DO UPDATE SET count = min(count + excluded.count, 9007199254740991),
			bg_count = min(bg_count + excluded.bg_count, 9007199254740991), rej_count = min(rej_count + excluded.rej_count, 9007199254740991),
			last_ms = CASE WHEN last_ms IS NULL OR excluded.last_ms > last_ms THEN excluded.last_ms ELSE last_ms END`,
			deviceID, k.hour, k.pkg, k.op, v.count, v.bg, v.rej, last); err != nil {
			return err
		}
	}
	for k, se := range apps {
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_latest(device_id, kind, key, ts_ms, data) VALUES(?,?,?,?,?)
			ON CONFLICT(device_id, kind, key) DO UPDATE SET ts_ms = excluded.ts_ms, data = excluded.data
			WHERE excluded.ts_ms >= app_latest.ts_ms`, deviceID, k.kind, k.key, se.TSms, string(se.Data)); err != nil {
			return err
		}
	}
	for h := range dirty {
		if err := markDirty(ctx, tx, deviceID, h); err != nil {
			return err
		}
	}
	return nil
}

func markDirty(ctx context.Context, tx *sql.Tx, deviceID string, hour int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO detect_dirty(device_id, hour_ms, gen) VALUES(?,?,0)
		ON CONFLICT(device_id, hour_ms) DO UPDATE SET gen = gen + 1`, deviceID, hour)
	return err
}

// markDirtyAll marks an hour for every device that is not revoked (AdGuard Home blocks, which are not tied
// to a device until they are crossed with its net.dns).
func markDirtyAll(ctx context.Context, tx *sql.Tx, hour int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO detect_dirty(device_id, hour_ms, gen)
		SELECT device_id, ?, 0 FROM devices WHERE revoked_ms IS NULL
		ON CONFLICT(device_id, hour_ms) DO UPDATE SET gen = gen + 1`, hour)
	return err
}

// DirtyHour is an hour of a device to evaluate again.
type DirtyHour struct {
	DeviceID string
	HourMS   int64
	Gen      int64
}

// DirtyHours returns at most limit hours to evaluate, per device and oldest first.
func (s *Store) DirtyHours(ctx context.Context, limit int) ([]DirtyHour, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT device_id, hour_ms, gen FROM detect_dirty ORDER BY device_id, hour_ms LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirtyHour
	for rows.Next() {
		var d DirtyHour
		if err := rows.Scan(&d.DeviceID, &d.HourMS, &d.Gen); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ClearDirty forgets the evaluated hours, except those marked again since they were read (a batch stored
// meanwhile): they stay to be evaluated at the next run.
func (s *Store) ClearDirty(ctx context.Context, hours []DirtyHour) error {
	if len(hours) == 0 {
		return nil
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, `DELETE FROM detect_dirty WHERE device_id = ? AND hour_ms = ? AND gen = ?`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, h := range hours {
		if _, err := st.ExecContext(ctx, h.DeviceID, h.HourMS, h.Gen); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DirtyCount returns the number of hours waiting for an evaluation.
func (s *Store) DirtyCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM detect_dirty`).Scan(&n)
	return n, err
}

// Detection is one finding to store (contract §11.3).
type Detection struct {
	DeviceID string
	Type     string
	// Subject identifies what the detection is about within its window (the application): (device, type,
	// subject, window start) is stored once and updated in place.
	Subject      string
	WindowFromMS int64
	WindowToMS   int64
	Package      string
	Label        string
	Sev          int
	Summary      string
	Evidence     map[string]any
	// Items are the elements of the detection (domains, capabilities…), kept as a growing set.
	Items []string
}

// DetectionReexport is the minimum delay between two exports of the same detection.
const DetectionReexport = time.Hour

// MaxDetectionsPerDay bounds the detections created per device and UTC day (contract §11.4); beyond, a single
// detect.flood per device and day counts what was suppressed.
const MaxDetectionsPerDay = 200

// TypeFlood is the detection that replaces the detections beyond MaxDetectionsPerDay.
const TypeFlood = "detect.flood"

// RecurringWindow: a detection of a recurring type whose (type, application) was already reported within this
// window is marked recurring, its severity capped at 1 (contract §11.4).
const RecurringWindow = 30 * 24 * time.Hour

// recurringTypes are the types subject to the recurrence rule.
var recurringTypes = map[string]bool{"detect.dns_bypass": true, "detect.mail_ports": true, "detect.upload_spike": true}

// UpsertResult tells what UpsertDetections did.
type UpsertResult struct {
	Events     []StoredEvent // events to publish (new detections and exported updates)
	Added      int
	Updated    int
	Muted      int // new detections stored muted (not exported)
	Suppressed int // new detections beyond the daily cap
}

// UpsertDetections stores findings, one per device, type, subject and window:
//   - a new finding is stored with its event of the collector (source "server", type = the detection type),
//     unless it is covered by a mute (stored with muted = 1, no event: neither exported nor streamed);
//   - of the recurring types, a new finding whose (type, subject) was already stored within RecurringWindow
//     before its window is marked recurring and its severity capped at 1;
//   - beyond MaxDetectionsPerDay new findings of a device during the UTC day of now, nothing more is stored but
//     one detect.flood (severity 3) per device and day, updated in place with the number suppressed;
//   - a finding already stored is updated in place (evidence, summary, label, highest severity, union of
//     its elements) when it differs; the update is exported again — a new event of the same type carrying
//     "update": true and "detection_id" — only when it is more severe or brings an element not exported yet,
//     at most once per DetectionReexport, and never while muted;
//   - an identical finding changes nothing (a window evaluated again after a late batch or a restart).
func (s *Store) UpsertDetections(ctx context.Context, ds []Detection, now time.Time) (UpsertResult, error) {
	var res UpsertResult
	if len(ds) == 0 {
		return res, nil
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	nowMS := now.UnixMilli()
	day := nowMS - mod(nowMS, 24*hourMS)
	changed := false
	for _, d := range ds {
		evidence, err := model.Marshal(d.Evidence)
		if err != nil {
			return res, err
		}
		var muteN int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM detect_mutes WHERE device_id = ? AND type = ? AND package = ?`,
			d.DeviceID, d.Type, d.Package).Scan(&muteN); err != nil {
			return res, err
		}
		muted := muteN > 0 && d.Package != "" && Mutable(d.Type)
		var id, label, summary, oldEvidence, itemsJSON, exportedJSON string
		var sev, exportedSev, wasMuted, recurring int
		var exportedMS int64
		err = tx.QueryRowContext(ctx, `SELECT id, label, summary, sev, evidence, items, exported_ms, exported_sev, exported_items, muted, recurring
			FROM detections WHERE device_id = ? AND type = ? AND subject = ? AND window_from_ms = ?`, d.DeviceID, d.Type, d.Subject, d.WindowFromMS).
			Scan(&id, &label, &summary, &sev, &oldEvidence, &itemsJSON, &exportedMS, &exportedSev, &exportedJSON, &wasMuted, &recurring)
		if errors.Is(err, sql.ErrNoRows) {
			var today int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM detections WHERE device_id = ? AND ts_ms >= ? AND ts_ms < ? AND type <> ?`,
				d.DeviceID, day, day+24*hourMS, TypeFlood).Scan(&today); err != nil {
				return res, err
			}
			if today >= MaxDetectionsPerDay {
				ev, err := flood(ctx, tx, d.DeviceID, day, now)
				if err != nil {
					return res, err
				}
				if ev != nil {
					res.Events = append(res.Events, *ev)
				}
				res.Suppressed++
				changed = true
				continue
			}
			if recurringTypes[d.Type] {
				var n int
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM detections WHERE device_id = ? AND type = ? AND subject = ?
					AND window_from_ms < ? AND window_from_ms >= ?`, d.DeviceID, d.Type, d.Subject, d.WindowFromMS,
					d.WindowFromMS-RecurringWindow.Milliseconds()).Scan(&n); err != nil {
					return res, err
				}
				if n > 0 {
					recurring = 1
					d.Sev = min(d.Sev, 1)
				}
			}
			items := unionItems(nil, d.Items)
			itemsRaw, _ := json.Marshal(items)
			var exported int64
			if muted {
				id = model.NewULID(now)
				res.Muted++
			} else {
				se, err := insertServerEvent(ctx, tx, d.DeviceID, d.Type, d.Sev, detectionData(d, "", false, recurring == 1), now)
				if err != nil {
					return res, err
				}
				id, exported = se.ID, se.TSms
				res.Events = append(res.Events, se)
				res.Added++
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO detections(id, device_id, type, subject, window_from_ms, window_to_ms, ts_ms, package,
				label, sev, summary, evidence, items, exported_ms, exported_sev, exported_items, muted, recurring) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				id, d.DeviceID, d.Type, d.Subject, d.WindowFromMS, d.WindowToMS, nowMS, d.Package, d.Label, d.Sev, d.Summary,
				string(evidence), string(itemsRaw), exported, d.Sev, string(itemsRaw), boolInt(muted), recurring); err != nil {
				return res, err
			}
			changed = true
			continue
		}
		if err != nil {
			return res, err
		}
		var stored, exported []string
		_ = json.Unmarshal([]byte(itemsJSON), &stored)
		_ = json.Unmarshal([]byte(exportedJSON), &exported)
		items := unionItems(stored, d.Items)
		newSev := max(sev, d.Sev)
		if recurring == 1 {
			newSev = min(newSev, 1)
		}
		if d.Label == "" {
			d.Label = label
		}
		if string(evidence) == oldEvidence && d.Summary == summary && newSev == sev && len(items) == len(stored) && d.Label == label &&
			wasMuted == boolInt(muted) {
			continue
		}
		itemsRaw, _ := json.Marshal(items)
		if _, err := tx.ExecContext(ctx, `UPDATE detections SET label = ?, sev = ?, summary = ?, evidence = ?, items = ?, updated_ms = ?, muted = ?
			WHERE id = ?`, d.Label, newSev, d.Summary, string(evidence), string(itemsRaw), nowMS, boolInt(muted), id); err != nil {
			return res, err
		}
		res.Updated++
		changed = true
		grew := newSev > exportedSev || len(unionItems(exported, items)) > len(exported)
		if muted || !grew || nowMS-exportedMS < DetectionReexport.Milliseconds() {
			continue
		}
		d.Sev = newSev
		se, err := insertServerEvent(ctx, tx, d.DeviceID, d.Type, newSev, detectionData(d, id, true, recurring == 1), now)
		if err != nil {
			return res, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE detections SET exported_ms = ?, exported_sev = ?, exported_items = ? WHERE id = ?`,
			nowMS, newSev, string(itemsRaw), id); err != nil {
			return res, err
		}
		res.Events = append(res.Events, se)
	}
	if !changed {
		return res, nil
	}
	return res, tx.Commit()
}

// flood records one suppressed detection in the detect.flood of the device and day (created, with its event,
// the first time; afterwards updated in place, never exported again).
func flood(ctx context.Context, tx *sql.Tx, deviceID string, day int64, now time.Time) (*StoredEvent, error) {
	var id, evidence string
	err := tx.QueryRowContext(ctx, `SELECT id, evidence FROM detections WHERE device_id = ? AND type = ? AND subject = '' AND window_from_ms = ?`,
		deviceID, TypeFlood, day).Scan(&id, &evidence)
	if err == nil {
		var ev struct {
			Suppressed int64 `json:"suppressed"`
		}
		_ = json.Unmarshal([]byte(evidence), &ev)
		ev.Suppressed++
		raw, _ := json.Marshal(map[string]any{"suppressed": ev.Suppressed, "limit": MaxDetectionsPerDay})
		_, err := tx.ExecContext(ctx, `UPDATE detections SET evidence = ?, summary = ?, updated_ms = ? WHERE id = ?`, string(raw),
			floodSummary(ev.Suppressed), now.UnixMilli(), id)
		return nil, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	d := Detection{DeviceID: deviceID, Type: TypeFlood, WindowFromMS: day, WindowToMS: day + 24*hourMS, Sev: 3, Summary: floodSummary(1),
		Evidence: map[string]any{"suppressed": 1, "limit": MaxDetectionsPerDay}}
	se, err := insertServerEvent(ctx, tx, deviceID, TypeFlood, 3, detectionData(d, "", false, false), now)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(d.Evidence)
	if _, err := tx.ExecContext(ctx, `INSERT INTO detections(id, device_id, type, subject, window_from_ms, window_to_ms, ts_ms, package,
		label, sev, summary, evidence, items, exported_ms, exported_sev, exported_items) VALUES(?,?,?,'',?,?,?,'','',3,?,?,'[]',?,3,'[]')`,
		se.ID, deviceID, TypeFlood, d.WindowFromMS, d.WindowToMS, se.TSms, d.Summary, string(raw), se.TSms); err != nil {
		return nil, err
	}
	return &se, nil
}

func floodSummary(n int64) string {
	return fmt.Sprintf("Plus de %d détections dans la journée pour cet appareil : %d de plus non enregistrées. L'appareil envoie des données incohérentes ou est compromis.",
		MaxDetectionsPerDay, n)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Unmutable types (contract §11.4): they cannot be muted from the console.
var unmutable = map[string]bool{"detect.sms_abuse": true, "detect.default_app_changed": true, "detect.inventory_mismatch": true, TypeFlood: true}

// Mutable reports whether detections of type t may be muted.
func Mutable(t string) bool { return !unmutable[t] }

// Mute is a mute set from the console.
type Mute struct {
	DeviceID  string `json:"device_id"`
	Type      string `json:"type"`
	Package   string `json:"package"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

// SetMute adds (or replaces the reason of) a mute and marks the detections it covers; with the event
// detect.muted when the mute is new. It returns ErrNotFound for an unknown device.
func (s *Store) SetMute(ctx context.Context, m Mute, now time.Time) (*StoredEvent, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE device_id = ?`, m.DeviceID).Scan(&n); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	r, err := tx.ExecContext(ctx, `INSERT INTO detect_mutes(device_id, type, package, reason, created_ms, created_by) VALUES(?,?,?,?,?,?)
		ON CONFLICT(device_id, type, package) DO NOTHING`, m.DeviceID, m.Type, m.Package, m.Reason, now.UnixMilli(), m.CreatedBy)
	if err != nil {
		return nil, err
	}
	created, _ := r.RowsAffected()
	if created == 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE detect_mutes SET reason = ? WHERE device_id = ? AND type = ? AND package = ?`,
			m.Reason, m.DeviceID, m.Type, m.Package); err != nil {
			return nil, err
		}
		return nil, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE detections SET muted = 1 WHERE device_id = ? AND type = ? AND package = ?`, m.DeviceID, m.Type, m.Package); err != nil {
		return nil, err
	}
	ev, err := insertServerEvent(ctx, tx, m.DeviceID, "detect.muted", 1,
		map[string]any{"type": m.Type, "package": m.Package, "reason": m.Reason, "user": m.CreatedBy}, now)
	if err != nil {
		return nil, err
	}
	return &ev, tx.Commit()
}

// DeleteMute lifts a mute (ErrNotFound when there is none), with the event detect.unmuted. The detections
// stored while muted stay unexported; the next ones are exported again.
func (s *Store) DeleteMute(ctx context.Context, deviceID, typ, pkg, user, reason string, now time.Time) (*StoredEvent, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `DELETE FROM detect_mutes WHERE device_id = ? AND type = ? AND package = ?`, deviceID, typ, pkg)
	if err != nil {
		return nil, err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE detections SET muted = 0 WHERE device_id = ? AND type = ? AND package = ?`, deviceID, typ, pkg); err != nil {
		return nil, err
	}
	ev, err := insertServerEvent(ctx, tx, deviceID, "detect.unmuted", 0,
		map[string]any{"type": typ, "package": pkg, "reason": reason, "user": user}, now)
	if err != nil {
		return nil, err
	}
	return &ev, tx.Commit()
}

// ListMutes returns the mutes (of one device when deviceID is set).
func (s *Store) ListMutes(ctx context.Context, deviceID string) ([]Mute, error) {
	q := `SELECT device_id, type, package, reason, created_ms, created_by FROM detect_mutes`
	var args []any
	if deviceID != "" {
		q += ` WHERE device_id = ?`
		args = append(args, deviceID)
	}
	rows, err := s.r.QueryContext(ctx, q+` ORDER BY device_id, type, package`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Mute{}
	for rows.Next() {
		var m Mute
		var ms int64
		if err := rows.Scan(&m.DeviceID, &m.Type, &m.Package, &m.Reason, &ms, &m.CreatedBy); err != nil {
			return nil, err
		}
		m.CreatedAt = fmtMS(ms)
		out = append(out, m)
	}
	return out, rows.Err()
}

// DetectionIn reports whether a detection (device, type, subject) exists whose window starts in
// [fromMS, toMS) (detect.sms_permission: one per holding of the permission).
func (s *Store) DetectionIn(ctx context.Context, deviceID, typ, subject string, fromMS, toMS int64) (bool, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM detections WHERE device_id = ? AND type = ? AND subject = ? AND window_from_ms >= ?
		AND window_from_ms < ?`, deviceID, typ, subject, fromMS, toMS).Scan(&n)
	return n > 0, err
}

// detectionData is the data of the event of a detection.
func detectionData(d Detection, id string, update, recurring bool) map[string]any {
	ev := map[string]any{"window_from": model.FormatMS(d.WindowFromMS), "window_to": model.FormatMS(d.WindowToMS),
		"summary": d.Summary, "evidence": d.Evidence}
	if d.Package != "" {
		ev["package"] = d.Package
	}
	if d.Label != "" {
		ev["label"] = d.Label
	}
	if update {
		ev["update"], ev["detection_id"] = true, id
	}
	if recurring {
		ev["recurring"] = true
	}
	return ev
}

// unionItems returns a ∪ b, in the order of a then b, without duplicates.
func unionItems(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	seen := map[string]bool{}
	for _, l := range [][]string{a, b} {
		for _, x := range l {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// --- reads of the detection engine ---------------------------------------------------------------

// maxDetectRows bounds the rows read for one evaluation.
const maxDetectRows = 500000

// HourlyTx returns the bytes sent (tx) per application during one hour of a device.
func (s *Store) HourlyTx(ctx context.Context, deviceID string, hourMS int64) (map[string]int64, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT package, tx_bytes FROM usage_counts WHERE hour_ms = ? AND device_id = ?`, hourMS, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var p string
		var tx int64
		if err := rows.Scan(&p, &tx); err != nil {
			return nil, err
		}
		out[p] = tx
	}
	return out, rows.Err()
}

// TxHistory returns the hourly bytes sent by an application in [fromMS, toMS) (hours with traffic only).
func (s *Store) TxHistory(ctx context.Context, deviceID, pkg string, fromMS, toMS int64) ([]int64, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT tx_bytes FROM usage_counts WHERE hour_ms >= ? AND hour_ms < ? AND device_id = ? AND package = ?`,
		fromMS, toMS, deviceID, pkg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var tx int64
		if err := rows.Scan(&tx); err != nil {
			return nil, err
		}
		out = append(out, tx)
	}
	return out, rows.Err()
}

// FirstUsageHour returns the first hour of net.usage stored for a device (false: none).
func (s *Store) FirstUsageHour(ctx context.Context, deviceID string) (int64, bool, error) {
	var h int64
	err := s.r.QueryRowContext(ctx, `SELECT hour_ms FROM usage_counts WHERE device_id = ? ORDER BY hour_ms LIMIT 1`, deviceID).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return h, err == nil, err
}

// ConnectRow is a destination (key "ip:port", "[ipv6]:port" or "ip") of an application, with its number of
// connections (weighted by data.count).
type ConnectRow struct {
	Package string
	Key     string
	Count   int64
}

// ConnectDests returns the net.connect destinations per application over the hours in [fromMS, toMS).
func (s *Store) ConnectDests(ctx context.Context, deviceID string, fromMS, toMS int64) ([]ConnectRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT package, key, SUM(count) FROM top_counts
		WHERE kind = 'connect_dest' AND hour_ms >= ? AND hour_ms < ? AND device_id = ? AND package <> ''
		GROUP BY package, key LIMIT ?`, fromMS, toMS, deviceID, maxDetectRows)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnectRow
	for rows.Next() {
		var r ConnectRow
		if err := rows.Scan(&r.Package, &r.Key, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ThreatBlock is a domain blocked by AdGuard Home due to a threat list.
type ThreatBlock struct {
	Domain  string
	Blocked int64
	Reason  string
}

// ThreatBlocks returns the domains blocked due to a threat list over the hours in [fromMS, toMS), for the
// given AdGuard Home clients (all when empty).
func (s *Store) ThreatBlocks(ctx context.Context, clients []string, fromMS, toMS int64) ([]ThreatBlock, error) {
	q := `SELECT domain, SUM(threat), max(reason) FROM tracking_counts WHERE hour_ms >= ? AND hour_ms < ? AND threat > 0`
	args := []any{fromMS, toMS}
	if len(clients) > 0 {
		q += ` AND client IN (?` + strings.Repeat(",?", len(clients)-1) + `)`
		for _, c := range clients {
			args = append(args, c)
		}
	}
	q += ` GROUP BY domain LIMIT 10000`
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ThreatBlock
	for rows.Next() {
		var b ThreatBlock
		if err := rows.Scan(&b.Domain, &b.Blocked, &b.Reason); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DNSLookup is the number of lookups of a domain by an application.
type DNSLookup struct {
	Package, Domain string
	Count           int64
}

// DNSLookupsOf returns the net.dns lookups of the given domains per application over [fromMS, toMS).
func (s *Store) DNSLookupsOf(ctx context.Context, deviceID string, domains []string, fromMS, toMS int64) ([]DNSLookup, error) {
	if len(domains) == 0 {
		return nil, nil
	}
	var out []DNSLookup
	for len(domains) > 0 {
		n := min(len(domains), 200)
		part := domains[:n]
		domains = domains[n:]
		args := []any{fromMS, toMS, deviceID}
		for _, d := range part {
			args = append(args, d)
		}
		rows, err := s.r.QueryContext(ctx, `SELECT package, key, SUM(count) FROM top_counts
			WHERE kind = 'dns_hostname' AND hour_ms >= ? AND hour_ms < ? AND device_id = ? AND package <> ''
			AND key IN (?`+strings.Repeat(",?", n-1)+`) GROUP BY package, key`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var l DNSLookup
			if err := rows.Scan(&l.Package, &l.Domain, &l.Count); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, l)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// OpUse is the use of an operation by an application (app.ops).
type OpUse struct {
	Package    string `json:"-"`
	Op         string `json:"op"`
	Count      int64  `json:"count"`
	Background int64  `json:"background_count"`
	Rejected   int64  `json:"rejected_count"`
	LastMS     int64  `json:"-"`
}

// OpsUses returns app.ops per application and operation over the hours in [fromMS, toMS) (all devices when
// deviceID is empty).
func (s *Store) OpsUses(ctx context.Context, deviceID string, fromMS, toMS int64) ([]OpUse, error) {
	q := `SELECT package, op, min(TOTAL(count), 9007199254740991), min(TOTAL(bg_count), 9007199254740991), min(TOTAL(rej_count), 9007199254740991), COALESCE(MAX(last_ms), 0)
		FROM ops_counts WHERE hour_ms >= ? AND hour_ms < ?`
	args := []any{fromMS, toMS}
	if deviceID != "" {
		q = `SELECT package, op, min(TOTAL(count), 9007199254740991), min(TOTAL(bg_count), 9007199254740991), min(TOTAL(rej_count), 9007199254740991), COALESCE(MAX(last_ms), 0)
		FROM ops_counts WHERE device_id = ? AND hour_ms >= ? AND hour_ms < ?`
		args = []any{deviceID, fromMS, toMS}
	}
	rows, err := s.r.QueryContext(ctx, q+` GROUP BY package, op LIMIT ?`, append(args, maxDetectRows)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OpUse
	for rows.Next() {
		var u OpUse
		var c, b, r float64
		if err := rows.Scan(&u.Package, &u.Op, &c, &b, &r, &u.LastMS); err != nil {
			return nil, err
		}
		u.Count, u.Background, u.Rejected = int64(c), int64(b), int64(r)
		out = append(out, u)
	}
	return out, rows.Err()
}

// AppLatest returns the latest app.risk (kind AppLatestRisk, by package) or app.role (AppLatestRole, by
// role) of a device.
func (s *Store) AppLatest(ctx context.Context, deviceID, kind string) (map[string]StoredEvent, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT key, ts_ms, data FROM app_latest WHERE device_id = ? AND kind = ?`, deviceID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]StoredEvent{}
	for rows.Next() {
		var key, data string
		var ts int64
		if err := rows.Scan(&key, &ts, &data); err != nil {
			return nil, err
		}
		out[key] = StoredEvent{DeviceID: deviceID, TSms: ts, Data: json.RawMessage(data)}
	}
	return out, rows.Err()
}

// --- console -------------------------------------------------------------------------------------

// DetectionItem is one entry of GET /detections.
type DetectionItem struct {
	PK         int64           `json:"-"`
	TSms       int64           `json:"-"`
	ID         string          `json:"id"`
	TS         string          `json:"ts"`
	DeviceID   string          `json:"device_id"`
	Type       string          `json:"type"`
	Package    string          `json:"package,omitempty"`
	Label      string          `json:"label,omitempty"`
	Severity   int             `json:"severity"`
	Summary    string          `json:"summary"`
	Evidence   json.RawMessage `json:"evidence"`
	WindowFrom string          `json:"window_from"`
	WindowTo   string          `json:"window_to"`
	UpdatedAt  string          `json:"updated_at,omitempty"`
	Muted      bool            `json:"muted"`
	Recurring  bool            `json:"recurring"`
}

// DetectionQuery selects detections for the console.
type DetectionQuery struct {
	DeviceID     string
	Package      string
	FromMS, ToMS int64
	TypePrefixes []string
	Limit        int
	HasCursor    bool
	CursorTS     int64
	CursorPK     int64
}

// ListDetections returns the detections found in [from, to] (time of the finding), newest first, and
// whether more follow.
func (s *Store) ListDetections(ctx context.Context, q DetectionQuery) ([]DetectionItem, bool, error) {
	where := []string{"ts_ms >= ?", "ts_ms <= ?"}
	args := []any{q.FromMS, q.ToMS}
	if q.DeviceID != "" {
		where = append(where, "device_id = ?")
		args = append(args, q.DeviceID)
	}
	if q.Package != "" {
		where = append(where, "package = ?")
		args = append(args, q.Package)
	}
	if len(q.TypePrefixes) > 0 {
		var ors []string
		for _, p := range q.TypePrefixes {
			ors = append(ors, `type LIKE ? ESCAPE '\'`)
			args = append(args, likeEscape(p)+"%")
		}
		where = append(where, "("+strings.Join(ors, " OR ")+")")
	}
	if q.HasCursor {
		where = append(where, "(ts_ms < ? OR (ts_ms = ? AND pk < ?))")
		args = append(args, q.CursorTS, q.CursorTS, q.CursorPK)
	}
	args = append(args, q.Limit+1)
	rows, err := s.r.QueryContext(ctx, `SELECT pk, id, ts_ms, device_id, type, package, label, sev, summary, evidence, window_from_ms, window_to_ms, updated_ms, muted, recurring
		FROM detections WHERE `+strings.Join(where, " AND ")+` ORDER BY ts_ms DESC, pk DESC LIMIT ?`, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []DetectionItem{}
	for rows.Next() {
		var d DetectionItem
		var evidence string
		var wf, wt int64
		var upd sql.NullInt64
		if err := rows.Scan(&d.PK, &d.ID, &d.TSms, &d.DeviceID, &d.Type, &d.Package, &d.Label, &d.Severity, &d.Summary, &evidence, &wf, &wt, &upd, &d.Muted, &d.Recurring); err != nil {
			return nil, false, err
		}
		if upd.Valid {
			d.UpdatedAt = fmtMS(upd.Int64)
		}
		d.TS, d.WindowFrom, d.WindowTo = fmtMS(d.TSms), fmtMS(wf), fmtMS(wt)
		d.Evidence = json.RawMessage(evidence)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(out) > q.Limit
	if more {
		out = out[:q.Limit]
	}
	return out, more, nil
}

// TxByHour returns the bytes sent per hour and application in [fromMS, toMS).
func (s *Store) TxByHour(ctx context.Context, deviceID string, fromMS, toMS int64) (map[int64]map[string]int64, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT hour_ms, package, tx_bytes FROM usage_counts WHERE hour_ms >= ? AND hour_ms < ? AND device_id = ?`,
		fromMS, toMS, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]map[string]int64{}
	for rows.Next() {
		var h, tx int64
		var p string
		if err := rows.Scan(&h, &p, &tx); err != nil {
			return nil, err
		}
		if out[h] == nil {
			out[h] = map[string]int64{}
		}
		out[h][p] = tx
	}
	return out, rows.Err()
}

// ConnectDestsByHour returns the net.connect destinations per hour and application in [fromMS, toMS).
func (s *Store) ConnectDestsByHour(ctx context.Context, deviceID string, fromMS, toMS int64) (map[int64][]ConnectRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT hour_ms, package, key, count FROM top_counts
		WHERE kind = 'connect_dest' AND hour_ms >= ? AND hour_ms < ? AND device_id = ? AND package <> '' LIMIT ?`,
		fromMS, toMS, deviceID, maxDetectRows)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]ConnectRow{}
	for rows.Next() {
		var h int64
		var r ConnectRow
		if err := rows.Scan(&h, &r.Package, &r.Key, &r.Count); err != nil {
			return nil, err
		}
		out[h] = append(out[h], r)
	}
	return out, rows.Err()
}
