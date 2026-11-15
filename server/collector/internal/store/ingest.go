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

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
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
}

// MarshalJSON renders the event for the console API.
func (e StoredEvent) MarshalJSON() ([]byte, error) {
	data := e.Data
	if len(data) == 0 {
		data = json.RawMessage(`{}`)
	}
	return json.Marshal(eventJSON{
		ID: e.ID, DeviceID: e.DeviceID, TS: model.FormatMS(e.TSms), ReceivedAt: model.FormatMS(e.ReceivedMS),
		Seq: e.Seq, BootID: e.BootID, ElapsedMS: e.ElapsedMS, Type: e.Type, Sev: e.Sev, Data: data,
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

type countKey struct {
	hour   int64
	typ    string
	sev    int
	kind   string
	key    string
	device string
}

type countVal struct{ count, bytes int64 }

// Ingest stores a batch of validated events for a device in one transaction.
// Each event is either inserted or recognized as a duplicate (same id).
// It returns the inserted events (in input order) and the number of duplicates.
func (s *Store) Ingest(ctx context.Context, deviceID, agentVersion string, evs []*model.Event, now time.Time) ([]StoredEvent, int, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()

	insEvent, err := tx.PrepareContext(ctx, `INSERT INTO events(id, device_id, ts_ms, received_ms, seq, boot_id, elapsed_ms, type, sev, data)
		VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`)
	if err != nil {
		return nil, 0, err
	}
	defer insEvent.Close()

	nowMS := now.UnixMilli()
	var stored []StoredEvent
	dups := 0
	counts := map[countKey]*countVal{}
	types := map[string]bool{}
	latest := map[string]StoredEvent{}
	var locs []locationRow

	add := func(k countKey, bytes int64) {
		v := counts[k]
		if v == nil {
			v = &countVal{}
			counts[k] = v
		}
		v.count++
		v.bytes += bytes
	}

	for _, ev := range evs {
		tsMS := ev.TS.UnixMilli()
		res, err := insEvent.ExecContext(ctx, ev.ID, deviceID, tsMS, nowMS, ev.Seq, ev.BootID, ev.ElapsedMS, ev.Type, ev.Sev, string(ev.Data))
		if err != nil {
			return nil, 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, 0, err
		}
		if n == 0 {
			dups++
			continue
		}
		pk, err := res.LastInsertId()
		if err != nil {
			return nil, 0, err
		}
		se := StoredEvent{PK: pk, ID: ev.ID, DeviceID: deviceID, TSms: tsMS, ReceivedMS: nowMS, Seq: ev.Seq,
			BootID: ev.BootID, ElapsedMS: ev.ElapsedMS, Type: ev.Type, Sev: ev.Sev, Data: ev.Data}
		stored = append(stored, se)

		hour := tsMS - mod(tsMS, hourMS)
		add(countKey{hour: hour, typ: ev.Type, sev: ev.Sev, device: deviceID}, 0)
		types[ev.Type] = true
		for _, tk := range topKeys(ev) {
			add(countKey{hour: hour, kind: tk.kind, key: tk.key, device: deviceID}, tk.bytes)
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
			return nil, 0, err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE devices SET last_seen_ms = ?, agent_version = COALESCE(NULLIF(?, ''), agent_version) WHERE device_id = ?`,
		nowMS, agentVersion, deviceID); err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return stored, dups, nil
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
			_, err = tx.ExecContext(ctx, `INSERT INTO top_counts(kind, hour_ms, device_id, key, count, bytes) VALUES(?,?,?,?,?,?)
				ON CONFLICT(kind, hour_ms, device_id, key) DO UPDATE SET count = count + excluded.count, bytes = bytes + excluded.bytes`,
				k.kind, k.hour, k.device, k.key, v.count, v.bytes)
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
	key   string
	bytes int64
}

// topKeys returns the aggregation keys contributed by one event to top_counts.
func topKeys(ev *model.Event) []topKey {
	d := ev.Decoded
	pkg, _ := model.Str(d, "package")
	pkg = clip(pkg, maxKeyLen)
	switch ev.Type {
	case "net.dns":
		var out []topKey
		if h, ok := model.Str(d, "hostname"); ok && h != "" {
			out = append(out, topKey{kind: TopDNSHostname, key: clip(strings.TrimSuffix(strings.ToLower(h), "."), maxKeyLen)})
		}
		if pkg != "" {
			out = append(out, topKey{kind: TopDNSPackage, key: pkg})
		}
		return out
	case "net.connect":
		var out []topKey
		if dest := connectDest(d); dest != "" {
			out = append(out, topKey{kind: TopConnectDest, key: dest})
		}
		if pkg != "" {
			out = append(out, topKey{kind: TopConnectPackage, key: pkg})
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
			b := max(rx, 0) + max(tx, 0)
			out = append(out, topKey{kind: TopUsagePackage, key: clip(p, maxKeyLen), bytes: b})
		}
		return out
	case "app.foreground":
		if e, _ := model.Str(d, "event"); e == "resumed" && pkg != "" {
			return []topKey{{kind: TopForegroundPackage, key: pkg}}
		}
	case "app.notification":
		if e, _ := model.Str(d, "event"); e == "posted" && pkg != "" {
			return []topKey{{kind: TopNotificationPackge, key: pkg}}
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
