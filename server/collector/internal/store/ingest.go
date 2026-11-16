package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/model"
)

const hourMS = int64(time.Hour / time.Millisecond)

// StoredEvent is an event as stored by the collector.
type StoredEvent struct {
	PK         int64
	ID         string
	DeviceID   string
	TSms       int64
	ReceivedMS int64
	Seq        int64
	BootID     string
	ElapsedMS  int64
	Type       string
	Sev        int
	Data       json.RawMessage
	// Source is "server" for the events produced by the collector itself (commands, contract §8), "" for
	// the events received from a device.
	Source string
}

// eventJSON is the console representation of an event (contract §6).
type eventJSON struct {
	ID         string          `json:"id"`
	DeviceID   string          `json:"device_id"`
	TS         string          `json:"ts"`
	ReceivedAt string          `json:"received_at"`
	Seq        int64           `json:"seq"`
	BootID     string          `json:"boot_id"`
	ElapsedMS  int64           `json:"elapsed_ms"`
	Type       string          `json:"type"`
	Sev        int             `json:"sev"`
	Data       json.RawMessage `json:"data"`
	Source     string          `json:"source,omitempty"`
}

// MarshalJSON renders the event for the console API.
func (e StoredEvent) MarshalJSON() ([]byte, error) {
	data := e.Data
	if len(data) == 0 {
		data = json.RawMessage(`{}`)
	}
	return json.Marshal(eventJSON{
		ID: e.ID, DeviceID: e.DeviceID, TS: model.FormatMS(e.TSms), ReceivedAt: model.FormatMS(e.ReceivedMS),
		Seq: e.Seq, BootID: e.BootID, ElapsedMS: e.ElapsedMS, Type: e.Type, Sev: e.Sev, Data: data, Source: e.Source,
	})
}

// Kinds of the top_counts table, matching the "kind" parameter of /stats/top.
const (
	TopDNSHostname        = "dns_hostname"
	TopDNSPackage         = "dns_package"
	TopConnectDest        = "connect_dest"
	TopConnectPackage     = "connect_package"
	TopUsagePackage       = "usage_package"
	TopForegroundPackage  = "foreground_package"
	TopNotificationPackge = "notification_package"
	TopEventType          = "event_type" // served from event_counts
)

const maxKeyLen = 255

// MaxEventCount bounds data.count, the number of identical occurrences an agent may group in one event.
const MaxEventCount = 1_000_000

// eventWeight returns the number of occurrences represented by an event of an aggregated type:
// data.count when it is an integer in [1, MaxEventCount], 1 otherwise (absent, fractional,
// out of range, or not a number). Migration 3 applies the same rule in SQL.
func eventWeight(d map[string]any) int64 {
	switch v := d["count"].(type) {
	case json.Number:
		if n, err := strconv.ParseInt(v.String(), 10, 64); err == nil && n >= 1 && n <= MaxEventCount {
			return n
		}
	case int64:
		if v >= 1 && v <= MaxEventCount {
			return v
		}
	case int:
		if v >= 1 && v <= MaxEventCount {
			return int64(v)
		}
	}
	return 1
}

type countKey struct {
	hour   int64
	typ    string
	sev    int
	kind   string
	pkg    string
	key    string
	device string
}

type countVal struct{ count, bytes int64 }

// IngestResult is the outcome of Store.Ingest.
type IngestResult struct {
	Stored     []StoredEvent // inserted events, in input order
	Duplicates int           // events whose id was already stored
	// Expired counts events acknowledged but not stored because their ts is older than the
	// retention window (the purge would delete them within the hour anyway).
	Expired int
}

// Ingest stores a batch of validated events for a device in one transaction.
// Each event is either inserted, recognized as a duplicate (same id) or dropped as expired.
//
// ts is the origin time of the event: events collected after the fact (net.dns, net.connect,
// security.log, app.foreground) arrive hours or days late, so every aggregate is keyed on ts
// and never on the reception time. An event older than the retention window (see SetRetention)
// is acknowledged without being stored.
func (s *Store) Ingest(ctx context.Context, deviceID, agentVersion string, evs []*model.Event, now time.Time) (IngestResult, error) {
	var res IngestResult
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()

	insEvent, err := tx.PrepareContext(ctx, `INSERT INTO events(id, device_id, ts_ms, received_ms, seq, boot_id, elapsed_ms, type, sev, data)
		VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`)
	if err != nil {
		return res, err
	}
	defer insEvent.Close()

	nowMS := now.UnixMilli()
	var stored []StoredEvent
	dups, expired := 0, 0
	cutoffMS := int64(math.MinInt64)
	if s.retention > 0 {
		cutoffMS = now.Add(-s.retention).UnixMilli()
	}
	counts := map[countKey]*countVal{}
	types := map[string]bool{}
	latest := map[string]StoredEvent{}
	var locs []locationRow
	usage := map[usageKey]*usageVal{}
	ops := map[opsKey]*opsVal{}
	apps := map[appKey]StoredEvent{}
	dirty := map[int64]bool{}

	add := func(k countKey, n, bytes int64) {
		v := counts[k]
		if v == nil {
			v = &countVal{}
			counts[k] = v
		}
		v.count += n
		v.bytes += bytes
	}

	for _, ev := range evs {
		tsMS := ev.TS.UnixMilli()
		if tsMS < cutoffMS {
			expired++
			continue
		}
		r, err := insEvent.ExecContext(ctx, ev.ID, deviceID, tsMS, nowMS, ev.Seq, ev.BootID, ev.ElapsedMS, ev.Type, ev.Sev, string(ev.Data))
		if err != nil {
			return res, err
		}
		n, err := r.RowsAffected()
		if err != nil {
			return res, err
		}
		if n == 0 {
			dups++
			continue
		}
		pk, err := r.LastInsertId()
		if err != nil {
			return res, err
		}
		se := StoredEvent{PK: pk, ID: ev.ID, DeviceID: deviceID, TSms: tsMS, ReceivedMS: nowMS, Seq: ev.Seq,
			BootID: ev.BootID, ElapsedMS: ev.ElapsedMS, Type: ev.Type, Sev: ev.Sev, Data: ev.Data}
		stored = append(stored, se)

		hour := tsMS - mod(tsMS, hourMS)
		add(countKey{hour: hour, typ: ev.Type, sev: ev.Sev, device: deviceID}, 1, 0) // timeline: events, not occurrences
		types[ev.Type] = true
		for _, tk := range topKeys(ev) {
			add(countKey{hour: hour, kind: tk.kind, pkg: tk.pkg, key: tk.key, device: deviceID}, tk.weight, tk.bytes)
		}
		if ev.Type == "net.usage" {
			addUsage(usage, hour, ev.Decoded)
		}
		if ev.Type == "app.ops" {
			addOps(ops, hour, ev.Decoded)
		}
		if k, ok := appLatestKey(ev); ok {
			if cur, seen := apps[k]; !seen || tsMS >= cur.TSms {
				apps[k] = se
			}
		}
		if DetectionInput(ev.Type) {
			dirty[hour] = true
		}
		if kind := latestKind(ev.Type); kind != "" {
			if cur, ok := latest[kind]; !ok || tsMS >= cur.TSms {
				latest[kind] = se
			}
		}
		if ev.Type == "location.fix" {
			if l, ok := locationFrom(pk, deviceID, tsMS, ev.Decoded); ok {
				locs = append(locs, l)
			}
		}
	}

	if len(stored) > 0 {
		if err := writeDerived(ctx, tx, deviceID, counts, types, latest, locs); err != nil {
			return res, err
		}
		if err := writeUsage(ctx, tx, deviceID, usage); err != nil {
			return res, err
		}
		if err := writeDetectInputs(ctx, tx, deviceID, ops, apps, dirty); err != nil {
			return res, err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE devices SET last_seen_ms = ?, agent_version = COALESCE(NULLIF(?, ''), agent_version) WHERE device_id = ?`,
		nowMS, agentVersion, deviceID); err != nil {
		return res, err
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	return IngestResult{Stored: stored, Duplicates: dups, Expired: expired}, nil
}

func writeDerived(ctx context.Context, tx *sql.Tx, deviceID string, counts map[countKey]*countVal,
	types map[string]bool, latest map[string]StoredEvent, locs []locationRow) error {
	for k, v := range counts {
		var err error
		if k.kind == "" {
			_, err = tx.ExecContext(ctx, `INSERT INTO event_counts(hour_ms, device_id, type, sev, count) VALUES(?,?,?,?,?)
				ON CONFLICT(hour_ms, device_id, type, sev) DO UPDATE SET count = count + excluded.count`,
				k.hour, k.device, k.typ, k.sev, v.count)
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO top_counts(kind, hour_ms, device_id, package, key, count, bytes) VALUES(?,?,?,?,?,?,?)
				ON CONFLICT(kind, hour_ms, device_id, package, key) DO UPDATE SET count = count + excluded.count,
				bytes = CASE WHEN top_counts.bytes > 9223372036854775807 - excluded.bytes THEN 9223372036854775807
					ELSE top_counts.bytes + excluded.bytes END`,
				k.kind, k.hour, k.device, k.pkg, k.key, v.count, v.bytes)
		}
		if err != nil {
			return err
		}
	}
	for t := range types {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO event_types(device_id, type) VALUES(?, ?)`, deviceID, t); err != nil {
			return err
		}
	}
	for kind, se := range latest {
		if _, err := tx.ExecContext(ctx, `INSERT INTO device_latest(device_id, kind, ts_ms, data) VALUES(?,?,?,?)
			ON CONFLICT(device_id, kind) DO UPDATE SET ts_ms = excluded.ts_ms, data = excluded.data
			WHERE excluded.ts_ms >= device_latest.ts_ms`, deviceID, kind, se.TSms, string(se.Data)); err != nil {
			return err
		}
	}
	for _, l := range locs {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO locations(event_pk, device_id, ts_ms, lat, lon, acc_m, speed_mps, provider, mock)
			VALUES(?,?,?,?,?,?,?,?,?)`, l.pk, l.device, l.ts, l.lat, l.lon, l.acc, l.speed, l.provider, l.mock); err != nil {
			return err
		}
	}
	return nil
}

type usageKey struct {
	hour int64
	pkg  string
}

type usageVal struct{ rx, tx int64 }

// addUsage accumulates the per-application byte counters of a net.usage event (tracking view, contract
// §9), clamped like the top_counts bytes.
func addUsage(acc map[usageKey]*usageVal, hour int64, d map[string]any) {
	apps, _ := d["apps"].([]any)
	for _, a := range apps {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		p, _ := model.Str(m, "package")
		if p == "" {
			continue
		}
		rx, _ := model.Int(m, "rx_bytes")
		tx, _ := model.Int(m, "tx_bytes")
		k := usageKey{hour: hour, pkg: clip(p, maxKeyLen)}
		v := acc[k]
		if v == nil {
			v = &usageVal{}
			acc[k] = v
		}
		v.rx = min(v.rx+clampBytes(rx), maxCountedBytes)
		v.tx = min(v.tx+clampBytes(tx), maxCountedBytes)
	}
}

func writeUsage(ctx context.Context, tx *sql.Tx, deviceID string, acc map[usageKey]*usageVal) error {
	for k, v := range acc {
		if _, err := tx.ExecContext(ctx, `INSERT INTO usage_counts(hour_ms, device_id, package, rx_bytes, tx_bytes) VALUES(?,?,?,?,?)
			ON CONFLICT(hour_ms, device_id, package) DO UPDATE SET rx_bytes = min(rx_bytes + excluded.rx_bytes, 9007199254740991),
			tx_bytes = min(tx_bytes + excluded.tx_bytes, 9007199254740991)`, k.hour, deviceID, k.pkg, v.rx, v.tx); err != nil {
			return err
		}
	}
	return nil
}

// Latest kinds kept per device for the /devices summary.
const (
	LatestHeartbeat = "heartbeat"
	LatestPosture   = "posture"
	LatestLocation  = "location"
	LatestInventory = "inventory"
)

func latestKind(t string) string {
	switch t {
	case "agent.heartbeat":
		return LatestHeartbeat
	case "security.posture":
		return LatestPosture
	case "location.fix":
		return LatestLocation
	case "device.inventory":
		return LatestInventory
	}
	return ""
}

type locationRow struct {
	pk       int64
	device   string
	ts       int64
	lat, lon float64
	acc      sql.NullFloat64
	speed    sql.NullFloat64
	provider sql.NullString
	mock     sql.NullInt64
}

func validFloat(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

func locationFrom(pk int64, device string, ts int64, d map[string]any) (locationRow, bool) {
	lat, ok1 := model.Num(d, "lat")
	lon, ok2 := model.Num(d, "lon")
	if !ok1 || !ok2 || !validFloat(lat) || !validFloat(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return locationRow{}, false
	}
	l := locationRow{pk: pk, device: device, ts: ts, lat: lat, lon: lon}
	if v, ok := model.Num(d, "acc_m"); ok && validFloat(v) {
		l.acc = sql.NullFloat64{Float64: v, Valid: true}
	}
	if v, ok := model.Num(d, "speed_mps"); ok && validFloat(v) {
		l.speed = sql.NullFloat64{Float64: v, Valid: true}
	}
	if v, ok := model.Str(d, "provider"); ok {
		l.provider = sql.NullString{String: clip(v, 32), Valid: true}
	}
	if v, ok := model.Bool(d, "mock"); ok {
		m := int64(0)
		if v {
			m = 1
		}
		l.mock = sql.NullInt64{Int64: m, Valid: true}
	}
	return l, true
}

type topKey struct {
	kind  string
	pkg   string // data.package of the event ("" if absent), for /stats/top?package=
	key   string
	bytes int64
	// weight is the number of occurrences counted (data.count for grouped events, otherwise 1).
	weight int64
}

// topKeys returns the aggregation keys contributed by one event to top_counts.
func topKeys(ev *model.Event) []topKey {
	d := ev.Decoded
	pkg, _ := model.Str(d, "package")
	pkg = clip(pkg, maxKeyLen)
	switch ev.Type {
	case "net.dns":
		w := eventWeight(d)
		var out []topKey
		if h, ok := model.Str(d, "hostname"); ok && h != "" {
			out = append(out, topKey{kind: TopDNSHostname, pkg: pkg, key: clip(strings.TrimSuffix(strings.ToLower(h), "."), maxKeyLen), weight: w})
		}
		if pkg != "" {
			out = append(out, topKey{kind: TopDNSPackage, pkg: pkg, key: pkg, weight: w})
		}
		return out
	case "net.connect":
		w := eventWeight(d)
		var out []topKey
		if dest := connectDest(d); dest != "" {
			out = append(out, topKey{kind: TopConnectDest, pkg: pkg, key: dest, weight: w})
		}
		if pkg != "" {
			out = append(out, topKey{kind: TopConnectPackage, pkg: pkg, key: pkg, weight: w})
		}
		return out
	case "net.usage":
		apps, _ := d["apps"].([]any)
		var out []topKey
		for _, a := range apps {
			m, ok := a.(map[string]any)
			if !ok {
				continue
			}
			p, _ := model.Str(m, "package")
			if p == "" {
				continue
			}
			rx, _ := model.Int(m, "rx_bytes")
			tx, _ := model.Int(m, "tx_bytes")
			// Clamped so that hostile values can neither wrap around nor make the SQL sums overflow.
			b := clampBytes(rx) + clampBytes(tx)
			out = append(out, topKey{kind: TopUsagePackage, pkg: clip(p, maxKeyLen), key: clip(p, maxKeyLen), bytes: b, weight: 1})
		}
		return out
	case "app.foreground":
		if e, _ := model.Str(d, "event"); e == "resumed" && pkg != "" {
			return []topKey{{kind: TopForegroundPackage, pkg: pkg, key: pkg, weight: 1}}
		}
	case "app.notification":
		if e, _ := model.Str(d, "event"); e == "posted" && pkg != "" {
			return []topKey{{kind: TopNotificationPackge, pkg: pkg, key: pkg, weight: 1}}
		}
	}
	return nil
}

func connectDest(d map[string]any) string {
	ip, _ := model.Str(d, "ip")
	if ip == "" {
		return ""
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		ip = a.String()
	} else {
		ip = clip(ip, 64)
	}
	port, ok := model.Int(d, "port")
	if !ok {
		return ip
	}
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.FormatInt(port, 10)
	}
	return ip + ":" + strconv.FormatInt(port, 10)
}

// maxCountedBytes bounds one byte counter (2^53 - 1, the largest integer exactly
// representable in JSON numbers on the console side).
const maxCountedBytes = 1<<53 - 1

func clampBytes(n int64) int64 { return min(max(n, 0), maxCountedBytes) }

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Do not cut in the middle of a UTF-8 sequence.
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}

func mod(a, b int64) int64 {
	m := a % b
	if m < 0 {
		m += b
	}
	return m
}
