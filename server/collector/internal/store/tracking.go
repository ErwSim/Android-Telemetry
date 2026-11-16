package store

import (
	"context"
	"strings"

	"github.com/erwsim/watchpost/server/collector/internal/tracking"
)

// TrackingRow is the AdGuard Home query log aggregated for one hour, client and domain.
type TrackingRow struct {
	HourMS  int64
	Client  string
	Domain  string
	Queries int64
	Blocked int64
	// Threat counts the queries blocked due to a list of category "threat" (or AdGuard Home's safe
	// browsing): they feed detect.threat_domain.
	Threat int64
	Reason string // latest readable reason ("" when none)
}

// ApplyTrackingPage adds a page of the AdGuard query log to the hourly aggregates and stores the reading
// position (kv stateKey) in the same transaction: after a crash, a page is either counted with its
// position or not at all.
func (s *Store) ApplyTrackingPage(ctx context.Context, rows []TrackingRow, stateKey, state string) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if len(rows) > 0 {
		st, err := tx.PrepareContext(ctx, `INSERT INTO tracking_counts(hour_ms, client, domain, queries, blocked, threat, reason) VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(hour_ms, client, domain) DO UPDATE SET queries = queries + excluded.queries, blocked = blocked + excluded.blocked,
			threat = threat + excluded.threat, reason = CASE WHEN excluded.reason <> '' THEN excluded.reason ELSE reason END`)
		if err != nil {
			return err
		}
		defer st.Close()
		threatHours := map[int64]bool{}
		for _, r := range rows {
			if _, err := st.ExecContext(ctx, r.HourMS, r.Client, r.Domain, r.Queries, r.Blocked, r.Threat, r.Reason); err != nil {
				return err
			}
			if r.Threat > 0 {
				threatHours[r.HourMS] = true
			}
		}
		// A block due to a threat list is crossed with the net.dns of each device by the detections.
		for h := range threatHours {
			if err := markDirtyAll(ctx, tx, h); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO kv(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		stateKey, state); err != nil {
		return err
	}
	return tx.Commit()
}

// maxTrackingRows bounds the rows read for one answer of the tracking view.
const maxTrackingRows = 500000

func hourRange(fromMS, toMS int64) (int64, int64) { return fromMS - mod(fromMS, hourMS), toMS }

// TrackingCounts returns the AdGuard aggregates per domain over the hours overlapping [from, to], for the
// given AdGuard clients (all when empty). The reason is the most recent non-empty one.
func (s *Store) TrackingCounts(ctx context.Context, clients []string, fromMS, toMS int64) (map[string]tracking.DomainCount, error) {
	start, end := hourRange(fromMS, toMS)
	q := `SELECT domain, SUM(queries), SUM(blocked), reason, max(CASE WHEN reason <> '' THEN hour_ms END)
		FROM tracking_counts WHERE hour_ms >= ? AND hour_ms <= ?`
	args := []any{start, end}
	if len(clients) > 0 {
		q += ` AND client IN (?` + strings.Repeat(",?", len(clients)-1) + `)`
		for _, c := range clients {
			args = append(args, c)
		}
	}
	q += ` GROUP BY domain LIMIT ?`
	args = append(args, maxTrackingRows)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]tracking.DomainCount{}
	for rows.Next() {
		var d, reason string
		var c tracking.DomainCount
		var last any
		if err := rows.Scan(&d, &c.Queries, &c.Blocked, &reason, &last); err != nil {
			return nil, err
		}
		c.Reason = reason
		out[d] = c
	}
	return out, rows.Err()
}

// DNSAppDomains returns the net.dns lookups per application and domain over the hours overlapping
// [from, to] (from the hourly aggregate kept at ingestion, weighted by data.count).
func (s *Store) DNSAppDomains(ctx context.Context, deviceID string, fromMS, toMS int64) ([]tracking.AppDomain, error) {
	start, end := hourRange(fromMS, toMS)
	q := `SELECT package, key, SUM(count) FROM top_counts WHERE kind = 'dns_hostname' AND hour_ms >= ? AND hour_ms <= ?`
	args := []any{start, end}
	if deviceID != "" {
		q += ` AND device_id = ?`
		args = append(args, deviceID)
	}
	q += ` GROUP BY package, key LIMIT ?`
	args = append(args, maxTrackingRows)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tracking.AppDomain
	for rows.Next() {
		var r tracking.AppDomain
		if err := rows.Scan(&r.Package, &r.Domain, &r.Count); err != nil {
			return nil, err
		}
		r.Domain = tracking.Normalize(r.Domain)
		if r.Domain != "" {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// UsageBytes returns the bytes received and sent per application over the hours overlapping [from, to].
func (s *Store) UsageBytes(ctx context.Context, deviceID string, fromMS, toMS int64) (map[string]tracking.Bytes, error) {
	start, end := hourRange(fromMS, toMS)
	q := `SELECT package, CAST(min(TOTAL(rx_bytes), 9.2e18) AS INTEGER), CAST(min(TOTAL(tx_bytes), 9.2e18) AS INTEGER)
		FROM usage_counts WHERE hour_ms >= ? AND hour_ms <= ?`
	args := []any{start, end}
	if deviceID != "" {
		q += ` AND device_id = ?`
		args = append(args, deviceID)
	}
	q += ` GROUP BY package`
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]tracking.Bytes{}
	for rows.Next() {
		var p string
		var b tracking.Bytes
		if err := rows.Scan(&p, &b.Rx, &b.Tx); err != nil {
			return nil, err
		}
		out[p] = b
	}
	return out, rows.Err()
}

// AppLabels returns package -> label from the latest inventory of a device (all devices when empty).
func (s *Store) AppLabels(ctx context.Context, deviceID string) (map[string]string, error) {
	devices := []string{deviceID}
	if deviceID == "" {
		ids, err := s.DeviceIDs(ctx)
		if err != nil {
			return nil, err
		}
		devices = ids
	}
	out := map[string]string{}
	for _, d := range devices {
		snap, err := s.LatestApps(ctx, d)
		if err != nil {
			return nil, err
		}
		for _, a := range snap.Apps {
			m, ok := a.(map[string]any)
			if !ok {
				continue
			}
			p, _ := m["package"].(string)
			l, _ := m["label"].(string)
			if p != "" && l != "" {
				out[p] = l
			}
		}
	}
	return out, nil
}
