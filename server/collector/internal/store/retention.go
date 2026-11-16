package store

import (
	"context"
	"time"
)

// PurgeResult summarizes a retention run.
type PurgeResult struct {
	Events int64
}

const purgeChunk = 5000

// Purge deletes events (and derived rows) whose timestamp is older than cutoff,
// and expired sessions. Deletion is chunked so the writer lock is never held long.
func (s *Store) Purge(ctx context.Context, cutoff, now time.Time, idle time.Duration) (PurgeResult, error) {
	var res PurgeResult
	c := cutoff.UnixMilli()
	devices, err := s.DeviceIDs(ctx)
	if err != nil {
		return res, err
	}
	for _, dev := range devices {
		for {
			r, err := s.w.ExecContext(ctx, `DELETE FROM events WHERE pk IN (
				SELECT pk FROM events INDEXED BY events_dev_ts WHERE device_id = ? AND ts_ms < ? LIMIT ?)`, dev, c, purgeChunk)
			if err != nil {
				return res, err
			}
			n, _ := r.RowsAffected()
			res.Events += n
			if n < purgeChunk {
				break
			}
			if err := ctx.Err(); err != nil {
				return res, err
			}
		}
		if _, err := s.w.ExecContext(ctx, `DELETE FROM locations WHERE device_id = ? AND ts_ms < ?`, dev, c); err != nil {
			return res, err
		}
	}
	// Orphan rows of events from devices that no longer exist are not expected
	// (devices are never deleted), so per-device deletion is complete.
	// The latest heartbeat, posture, position and inventory are copies of events:
	// they follow the same retention.
	if _, err := s.w.ExecContext(ctx, `DELETE FROM device_latest WHERE ts_ms < ?`, c); err != nil {
		return res, err
	}
	hourCut := c - mod(c, hourMS)
	for _, q := range []string{
		`DELETE FROM event_counts WHERE hour_ms < ?`,
		`DELETE FROM top_counts WHERE hour_ms < ?`,
		`DELETE FROM usage_counts WHERE hour_ms < ?`,
		`DELETE FROM tracking_counts WHERE hour_ms < ?`,
		`DELETE FROM ops_counts WHERE hour_ms < ?`,
		`DELETE FROM detect_dirty WHERE hour_ms < ?`,
		// A detection is kept as long as its window or the moment it was found is within the retention.
		`DELETE FROM detections WHERE window_to_ms < ?1 AND ts_ms < ?1`,
		// The latest app.risk and app.role are copies of events: they follow the same retention.
		`DELETE FROM app_latest WHERE ts_ms < ?`,
		// A command is kept at least until it expires, so that its id cannot be reused while it is valid.
		`DELETE FROM commands WHERE expires_ms < ?`,
	} {
		if _, err := s.w.ExecContext(ctx, q, hourCut); err != nil {
			return res, err
		}
	}
	if _, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE expires_ms <= ? OR last_seen_ms <= ?`,
		now.UnixMilli(), now.Add(-idle).UnixMilli()); err != nil {
		return res, err
	}
	if res.Events > 0 {
		_, _ = s.w.ExecContext(ctx, `PRAGMA incremental_vacuum(2000)`)
	}
	_, _ = s.w.ExecContext(ctx, `PRAGMA optimize`)
	return res, nil
}
