package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
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
		"app.special_access", "app.role":
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

// UpsertResult tells what UpsertDetections did.
type UpsertResult struct {
	Events  []StoredEvent // events to publish (new detections and exported updates)
	Added   int
	Updated int
}

// UpsertDetections stores findings, one per device, type, subject and window:
//   - a new finding is stored with its event of the collector (source "server", type = the detection type);
//   - a finding already stored is updated in place (evidence, summary, label, highest severity, union of
//     its elements) when it differs; the update is exported again — a new event of the same type carrying
//     "update": true and "detection_id" — only when it is more severe or brings an element not exported yet,
//     and at most once per DetectionReexport (what is held back is exported by a later update of the window);
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
	for _, d := range ds {
		evidence, err := model.Marshal(d.Evidence)
		if err != nil {
			return res, err
		}
		var id, label, summary, oldEvidence, itemsJSON, exportedJSON string
		var sev, exportedSev int
		var exportedMS int64
		err = tx.QueryRowContext(ctx, `SELECT id, label, summary, sev, evidence, items, exported_ms, exported_sev, exported_items FROM detections
			WHERE device_id = ? AND type = ? AND subject = ? AND window_from_ms = ?`, d.DeviceID, d.Type, d.Subject, d.WindowFromMS).
			Scan(&id, &label, &summary, &sev, &oldEvidence, &itemsJSON, &exportedMS, &exportedSev, &exportedJSON)
		if errors.Is(err, sql.ErrNoRows) {
			items := unionItems(nil, d.Items)
			se, err := insertServerEvent(ctx, tx, d.DeviceID, d.Type, d.Sev, detectionData(d, "", false), now)
			if err != nil {
				return res, err
			}
			itemsRaw, _ := json.Marshal(items)
			if _, err := tx.ExecContext(ctx, `INSERT INTO detections(id, device_id, type, subject, window_from_ms, window_to_ms, ts_ms, package,
				label, sev, summary, evidence, items, exported_ms, exported_sev, exported_items) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				se.ID, d.DeviceID, d.Type, d.Subject, d.WindowFromMS, d.WindowToMS, se.TSms, d.Package, d.Label, d.Sev, d.Summary,
				string(evidence), string(itemsRaw), se.TSms, d.Sev, string(itemsRaw)); err != nil {
				return res, err
			}
			res.Events = append(res.Events, se)
			res.Added++
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
		if d.Label == "" {
			d.Label = label
		}
		if string(evidence) == oldEvidence && d.Summary == summary && newSev == sev && len(items) == len(stored) && d.Label == label {
			continue
		}
		itemsRaw, _ := json.Marshal(items)
		if _, err := tx.ExecContext(ctx, `UPDATE detections SET label = ?, sev = ?, summary = ?, evidence = ?, items = ?, updated_ms = ?
			WHERE id = ?`, d.Label, newSev, d.Summary, string(evidence), string(itemsRaw), nowMS, id); err != nil {
			return res, err
		}
		res.Updated++
		grew := newSev > exportedSev || len(unionItems(exported, items)) > len(exported)
		if !grew || nowMS-exportedMS < DetectionReexport.Milliseconds() {
			continue
		}
		d.Sev = newSev
		se, err := insertServerEvent(ctx, tx, d.DeviceID, d.Type, newSev, detectionData(d, id, true), now)
		if err != nil {
			return res, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE detections SET exported_ms = ?, exported_sev = ?, exported_items = ? WHERE id = ?`,
			nowMS, newSev, string(itemsRaw), id); err != nil {
			return res, err
		}
		res.Events = append(res.Events, se)
	}
	if res.Added == 0 && res.Updated == 0 {
		return res, nil
	}
	return res, tx.Commit()
}

// detectionData is the data of the event of a detection.
func detectionData(d Detection, id string, update bool) map[string]any {
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
	rows, err := s.r.QueryContext(ctx, `SELECT pk, id, ts_ms, device_id, type, package, label, sev, summary, evidence, window_from_ms, window_to_ms, updated_ms
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
		if err := rows.Scan(&d.PK, &d.ID, &d.TSms, &d.DeviceID, &d.Type, &d.Package, &d.Label, &d.Severity, &d.Summary, &evidence, &wf, &wt, &upd); err != nil {
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
