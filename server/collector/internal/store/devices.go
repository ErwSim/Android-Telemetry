package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Device is an enrolled device.
type Device struct {
	DeviceID     string
	Name         string
	TokenHash    []byte
	CertSHA256   string
	CertPEM      string
	EnrolledAt   time.Time
	RevokedAt    *time.Time
	LastSeen     *time.Time
	AgentVersion string
}

// Revoked reports whether the device has been revoked.
func (d *Device) Revoked() bool { return d.RevokedAt != nil }

const deviceCols = `device_id, name, token_hash, cert_sha256, cert_pem, enrolled_ms, revoked_ms, last_seen_ms, COALESCE(agent_version, '')`

func scanDevice(sc interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	var enrolled int64
	var revoked, seen sql.NullInt64
	if err := sc.Scan(&d.DeviceID, &d.Name, &d.TokenHash, &d.CertSHA256, &d.CertPEM, &enrolled, &revoked, &seen, &d.AgentVersion); err != nil {
		return nil, err
	}
	d.EnrolledAt = time.UnixMilli(enrolled).UTC()
	if revoked.Valid {
		t := time.UnixMilli(revoked.Int64).UTC()
		d.RevokedAt = &t
	}
	if seen.Valid {
		t := time.UnixMilli(seen.Int64).UTC()
		d.LastSeen = &t
	}
	return &d, nil
}

// CreateDevice inserts a new device.
func (s *Store) CreateDevice(ctx context.Context, d *Device) error {
	_, err := s.w.ExecContext(ctx,
		`INSERT INTO devices(device_id, name, token_hash, cert_sha256, cert_pem, enrolled_ms) VALUES(?,?,?,?,?,?)`,
		d.DeviceID, d.Name, d.TokenHash, d.CertSHA256, d.CertPEM, d.EnrolledAt.UnixMilli())
	return err
}

// DeviceByTokenHash returns the device owning the token hash (revoked or not).
// It always reads the database, so a revocation made by the CLI in another
// process is effective on the next request.
func (s *Store) DeviceByTokenHash(ctx context.Context, hash []byte) (*Device, error) {
	d, err := scanDevice(s.r.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE token_hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// GetDevice returns one device.
func (s *Store) GetDevice(ctx context.Context, id string) (*Device, error) {
	d, err := scanDevice(s.r.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE device_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// ListDevices returns all devices ordered by enrollment date.
func (s *Store) ListDevices(ctx context.Context) ([]*Device, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices ORDER BY enrolled_ms, device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeviceIDs returns all device identifiers.
func (s *Store) DeviceIDs(ctx context.Context) ([]string, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT device_id FROM devices ORDER BY device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RevokeDevice marks a device revoked. It returns ErrNotFound for unknown devices
// and leaves an existing revocation date untouched.
func (s *Store) RevokeDevice(ctx context.Context, id string, now time.Time) error {
	res, err := s.w.ExecContext(ctx,
		`UPDATE devices SET revoked_ms = COALESCE(revoked_ms, ?) WHERE device_id = ?`, now.UnixMilli(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchDevice records the last contact time and agent version (used by ping).
func (s *Store) TouchDevice(ctx context.Context, id, agentVersion string, now time.Time) error {
	_, err := s.w.ExecContext(ctx,
		`UPDATE devices SET last_seen_ms = ?, agent_version = COALESCE(NULLIF(?, ''), agent_version) WHERE device_id = ?`,
		now.UnixMilli(), agentVersion, id)
	return err
}
