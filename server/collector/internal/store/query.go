package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/erwsim/watchpost/server/collector/internal/model"
)

func fmtMS(ms int64) string { return model.FormatMS(ms) }

// EventQuery are the filters of GET /events.
type EventQuery struct {
	DeviceID     string   // empty: all devices
	TypePrefixes []string // empty: all types
	SevMin       int
	FromMS, ToMS int64 // inclusive bounds
	Q            string
	Limit        int
	// Cursor: return events strictly older than (CursorTS, CursorPK) in (ts, pk) order.
	HasCursor bool
	CursorTS  int64
	CursorPK  int64
}

const eventCols = `pk, id, device_id, ts_ms, received_ms, seq, boot_id, elapsed_ms, type, sev, data, COALESCE(source, '')`

func scanEvent(sc interface{ Scan(...any) error }) (StoredEvent, error) {
	var e StoredEvent
	var data string
	err := sc.Scan(&e.PK, &e.ID, &e.DeviceID, &e.TSms, &e.ReceivedMS, &e.Seq, &e.BootID, &e.ElapsedMS, &e.Type, &e.Sev, &data, &e.Source)
	e.Data = json.RawMessage(data)
	return e, err
}

// stream is one ordered index scan whose results are merged with the others.
type stream struct {
	where string
	args  []any
	index string
}

// QueryEvents returns events matching q, newest first, plus whether more remain.
//
// Queries are decomposed into several "streams", each an ordered scan of one
// index range (per device, and per exact type or per severity when filtered),
// read with LIMIT n+1 and merged in Go. This keeps every query an ordered index
// walk, so rare types stay fast among millions of net.dns rows.
func (s *Store) QueryEvents(ctx context.Context, q EventQuery) ([]StoredEvent, bool, error) {
	devices := []string{q.DeviceID}
	if q.DeviceID == "" {
		ids, err := s.DeviceIDs(ctx)
		if err != nil {
			return nil, false, err
		}
		devices = ids
	}
	var streams []stream
	switch {
	case len(q.TypePrefixes) > 0:
		for _, dev := range devices {
			types, err := s.typesFor(ctx, dev, q.TypePrefixes)
			if err != nil {
				return nil, false, err
			}
			for _, t := range types {
				streams = append(streams, stream{where: "device_id = ? AND type = ?", args: []any{dev, t}, index: "events_dev_type_ts"})
			}
		}
	case q.SevMin > 0:
		for _, dev := range devices {
			for sev := q.SevMin; sev <= 3; sev++ {
				streams = append(streams, stream{where: "device_id = ? AND sev > 0 AND sev = ?", args: []any{dev, sev}, index: "events_dev_sev_ts"})
			}
		}
	default:
		for _, dev := range devices {
			streams = append(streams, stream{where: "device_id = ?", args: []any{dev}, index: "events_dev_ts"})
		}
	}

	upper := q.ToMS
	if q.HasCursor && q.CursorTS < upper {
		upper = q.CursorTS
	}
	var merged []StoredEvent
	for _, st := range streams {
		where := st.where + " AND ts_ms >= ? AND ts_ms <= ?"
		args := append(append([]any{}, st.args...), q.FromMS, upper)
		if q.HasCursor {
			where += " AND NOT (ts_ms = ? AND pk >= ?)"
			args = append(args, q.CursorTS, q.CursorPK)
		}
		if q.SevMin > 0 && len(q.TypePrefixes) > 0 {
			where += " AND sev >= ?"
			args = append(args, q.SevMin)
		}
		if q.Q != "" {
			where += ` AND data LIKE ? ESCAPE '\'`
			args = append(args, "%"+likeEscape(q.Q)+"%")
		}
		args = append(args, q.Limit+1)
		query := `SELECT ` + eventCols + ` FROM events INDEXED BY ` + st.index + ` WHERE ` + where +
			` ORDER BY ts_ms DESC, pk DESC LIMIT ?`
		rows, err := s.r.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, false, err
		}
		for rows.Next() {
			e, err := scanEvent(rows)
			if err != nil {
				rows.Close()
				return nil, false, err
			}
			merged = append(merged, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, false, err
		}
		// Keep memory bounded: only the newest limit+1 overall can be returned.
		if len(merged) > 4*(q.Limit+1) {
			sortEvents(merged)
			merged = merged[:q.Limit+1]
		}
	}
	sortEvents(merged)
	more := len(merged) > q.Limit
	if more {
		merged = merged[:q.Limit]
	}
	return merged, more, nil
}

func sortEvents(evs []StoredEvent) {
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].TSms != evs[j].TSms {
			return evs[i].TSms > evs[j].TSms
		}
		return evs[i].PK > evs[j].PK
	})
}

// typesFor expands type prefixes into the exact types seen for a device.
func (s *Store) typesFor(ctx context.Context, dev string, prefixes []string) ([]string, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT type FROM event_types WHERE device_id = ?`, dev)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		for _, p := range prefixes {
			if strings.HasPrefix(t, p) {
				out = append(out, t)
				break
			}
		}
	}
	return out, rows.Err()
}

func matchPrefixes(t string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// GetEvent returns one event by id.
func (s *Store) GetEvent(ctx context.Context, id string) (StoredEvent, error) {
	e, err := scanEvent(s.r.QueryRowContext(ctx, `SELECT `+eventCols+` FROM events WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// EventsAfter returns up to limit events with pk > after, in pk order (used by the exporter).
func (s *Store) EventsAfter(ctx context.Context, after int64, limit int) ([]StoredEvent, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+eventCols+` FROM events WHERE pk > ? ORDER BY pk LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredEvent
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// MaxEventPK returns the highest event pk ever assigned (0 if none).
func (s *Store) MaxEventPK(ctx context.Context) (int64, error) {
	var n sql.NullInt64
	err := s.r.QueryRowContext(ctx, `SELECT seq FROM sqlite_sequence WHERE name = 'events'`).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n.Int64, err
}

// DeviceNames returns a map device_id -> name.
func (s *Store) DeviceNames(ctx context.Context) (map[string]string, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT device_id, name FROM devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}

// Point is one location for GET /locations.
type Point struct {
	DeviceID string   `json:"device_id"`
	TS       string   `json:"ts"`
	Lat      float64  `json:"lat"`
	Lon      float64  `json:"lon"`
	AccM     *float64 `json:"acc_m,omitempty"`
	SpeedMPS *float64 `json:"speed_mps,omitempty"`
	Provider string   `json:"provider,omitempty"`
	Mock     bool     `json:"mock,omitempty"`
	tsMS     int64
}

// Locations returns location points in [from, to], oldest first, regularly
// sub-sampled to at most maxPoints (first and last points always kept).
func (s *Store) Locations(ctx context.Context, deviceID string, fromMS, toMS int64, maxPoints int) ([]Point, error) {
	where, args := "ts_ms >= ? AND ts_ms <= ?", []any{fromMS, toMS}
	if deviceID != "" {
		where = "device_id = ? AND " + where
		args = append([]any{deviceID}, args...)
	}
	var total int
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM locations WHERE `+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT device_id, ts_ms, lat, lon, acc_m, speed_mps, COALESCE(provider, ''), COALESCE(mock, 0)
		FROM locations WHERE `+where+` ORDER BY ts_ms, event_pk`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Point, 0, min(total, maxPoints))
	next, picked := 0, 0 // index of the next row to keep
	pick := func(k int) int {
		if total <= maxPoints {
			return k
		}
		if maxPoints == 1 {
			return total - 1
		}
		return int(int64(k) * int64(total-1) / int64(maxPoints-1))
	}
	next = pick(0)
	for i := 0; rows.Next(); i++ {
		if i != next {
			continue
		}
		var p Point
		var acc, speed sql.NullFloat64
		var mock int64
		if err := rows.Scan(&p.DeviceID, &p.tsMS, &p.Lat, &p.Lon, &acc, &speed, &p.Provider, &mock); err != nil {
			return nil, err
		}
		p.TS = fmtMS(p.tsMS)
		if acc.Valid {
			p.AccM = &acc.Float64
		}
		if speed.Valid {
			p.SpeedMPS = &speed.Float64
		}
		p.Mock = mock != 0
		out = append(out, p)
		picked++
		if picked >= maxPoints {
			break
		}
		next = pick(picked)
	}
	return out, rows.Err()
}

// Timeline counts events per bucket.
type Timeline struct {
	Buckets []string        `json:"buckets"`
	Series  []TimelineSerie `json:"series"`
}

// TimelineSerie is one series of a timeline.
type TimelineSerie struct {
	Key    string  `json:"key"`
	Counts []int64 `json:"counts"`
	total  int64
}

// TimelineQuery are the parameters of /stats/timeline.
type TimelineQuery struct {
	DeviceID     string
	FromMS, ToMS int64
	BucketMS     int64 // 60000, 3600000 or 86400000
	By           string
	TypePrefixes []string // optional filter, as in /events
}

// MaxTimelineBuckets bounds the size of a timeline answer.
const MaxTimelineBuckets = 2000

// StatsTimeline returns event counts per bucket. Buckets are aligned on UTC
// boundaries; hour and day buckets are served from the hourly aggregate.
func (s *Store) StatsTimeline(ctx context.Context, q TimelineQuery) (*Timeline, error) {
	start := q.FromMS - mod(q.FromMS, q.BucketMS)
	n := int((q.ToMS-start)/q.BucketMS) + 1
	if n > MaxTimelineBuckets || n < 1 {
		return nil, fmt.Errorf("trop d'intervalles (%d)", n)
	}
	tl := &Timeline{Buckets: make([]string, n), Series: []TimelineSerie{}}
	for i := range n {
		tl.Buckets[i] = fmtMS(start + int64(i)*q.BucketMS)
	}
	series := map[string]*TimelineSerie{}
	addCount := func(ts int64, typ string, sev int, c int64) {
		if ts < start || ts > q.ToMS || !matchPrefixes(typ, q.TypePrefixes) {
			return
		}
		idx := int((ts - start) / q.BucketMS)
		if idx < 0 || idx >= n {
			return
		}
		var key string
		switch q.By {
		case "type":
			key = typ
		case "sev":
			key = fmt.Sprint(sev)
		default:
			key = domainOf(typ)
		}
		se := series[key]
		if se == nil {
			se = &TimelineSerie{Key: key, Counts: make([]int64, n)}
			series[key] = se
		}
		se.Counts[idx] += c
		se.total += c
	}

	if q.BucketMS < hourMS {
		devices := []string{q.DeviceID}
		if q.DeviceID == "" {
			ids, err := s.DeviceIDs(ctx)
			if err != nil {
				return nil, err
			}
			devices = ids
		}
		for _, dev := range devices {
			rows, err := s.r.QueryContext(ctx, `SELECT ts_ms, type, sev FROM events INDEXED BY events_dev_ts
				WHERE device_id = ? AND ts_ms >= ? AND ts_ms <= ?`, dev, start, q.ToMS)
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var ts int64
				var typ string
				var sev int
				if err := rows.Scan(&ts, &typ, &sev); err != nil {
					rows.Close()
					return nil, err
				}
				addCount(ts, typ, sev, 1)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return nil, err
			}
		}
	} else {
		where, args := "hour_ms >= ? AND hour_ms <= ?", []any{start, q.ToMS}
		if q.DeviceID != "" {
			where += " AND device_id = ?"
			args = append(args, q.DeviceID)
		}
		rows, err := s.r.QueryContext(ctx, `SELECT hour_ms, type, sev, SUM(count) FROM event_counts WHERE `+where+
			` GROUP BY hour_ms, type, sev`, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var h, c int64
			var typ string
			var sev int
			if err := rows.Scan(&h, &typ, &sev, &c); err != nil {
				return nil, err
			}
			addCount(h, typ, sev, c)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	for _, se := range series {
		tl.Series = append(tl.Series, *se)
	}
	sort.Slice(tl.Series, func(i, j int) bool {
		if tl.Series[i].total != tl.Series[j].total {
			return tl.Series[i].total > tl.Series[j].total
		}
		return tl.Series[i].Key < tl.Series[j].Key
	})
	return tl, nil
}

// TopItem is one entry of /stats/top.
type TopItem struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
	Bytes *int64 `json:"bytes,omitempty"`
}

// ValidTopKind reports whether kind is supported by StatsTop.
func ValidTopKind(kind string) bool {
	switch kind {
	case TopDNSHostname, TopDNSPackage, TopConnectDest, TopConnectPackage, TopUsagePackage,
		TopForegroundPackage, TopNotificationPackge, TopEventType:
		return true
	}
	return false
}

// StatsTop returns the most frequent keys of a kind over the hours overlapping
// [from, to], optionally restricted to events whose data.package is pkg
// (not supported for event_type).
func (s *Store) StatsTop(ctx context.Context, deviceID, kind, pkg string, fromMS, toMS int64, limit int) ([]TopItem, error) {
	start := fromMS - mod(fromMS, hourMS)
	var query string
	var args []any
	if kind == TopEventType {
		query = `SELECT type, SUM(count), 0 FROM event_counts WHERE hour_ms >= ? AND hour_ms <= ?`
		args = []any{start, toMS}
	} else {
		// TOTAL (floating point) never fails on overflow, unlike SUM; the cast saturates.
		query = `SELECT key, SUM(count), CAST(min(TOTAL(bytes), 9.2e18) AS INTEGER) FROM top_counts
			WHERE kind = ? AND hour_ms >= ? AND hour_ms <= ?`
		args = []any{kind, start, toMS}
	}
	if deviceID != "" {
		query += " AND device_id = ?"
		args = append(args, deviceID)
	}
	if pkg != "" && kind != TopEventType {
		query += " AND package = ?"
		args = append(args, pkg)
	}
	order := "2 DESC, 1"
	if kind == TopUsagePackage {
		order = "3 DESC, 1"
	}
	query += " GROUP BY 1 ORDER BY " + order + " LIMIT ?"
	args = append(args, limit)
	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TopItem{}
	for rows.Next() {
		var it TopItem
		var b int64
		if err := rows.Scan(&it.Key, &it.Count, &b); err != nil {
			return nil, err
		}
		if kind == TopUsagePackage {
			it.Bytes = &b
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// Latest returns the most recent stored payload of a kind for a device.
func (s *Store) Latest(ctx context.Context, deviceID string) (map[string]StoredEvent, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT kind, ts_ms, data FROM device_latest WHERE device_id = ?`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]StoredEvent{}
	for rows.Next() {
		var kind, data string
		var ts int64
		if err := rows.Scan(&kind, &ts, &data); err != nil {
			return nil, err
		}
		out[kind] = StoredEvent{DeviceID: deviceID, TSms: ts, Data: json.RawMessage(data)}
	}
	return out, rows.Err()
}

// EventsOfType returns events of one exact type for a device in [from, to],
// newest first, at most limit.
func (s *Store) EventsOfType(ctx context.Context, deviceID, typ string, fromMS, toMS int64, limit int) ([]StoredEvent, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+eventCols+` FROM events INDEXED BY events_dev_type_ts
		WHERE device_id = ? AND type = ? AND ts_ms >= ? AND ts_ms <= ? ORDER BY ts_ms DESC, pk DESC LIMIT ?`,
		deviceID, typ, fromMS, toMS, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredEvent
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func domainOf(t string) string {
	if i := strings.IndexByte(t, '.'); i > 0 {
		return t[:i]
	}
	return t
}
