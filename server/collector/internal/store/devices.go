package store

import (
	"context"
	"crypto/subtle"
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

	// Pending renewal (contract §4): a second credential pair, accepted together with the current one
	// until the first authenticated request that uses it.
	NextTokenHash  []byte
	NextCertSHA256 string
	NextCertPEM    string
	NextIssuedAt   *time.Time

	// ViaPending is set by DeviceByTokenHash when the presented token is the pending one: the
	// certificate must then be checked against NextCertSHA256, never CertSHA256.
	ViaPending bool
}

// HasPending reports whether a renewal is waiting for its first use.
func (d *Device) HasPending() bool { return len(d.NextTokenHash) > 0 }

// Revoked reports whether the device has been revoked.
func (d *Device) Revoked() bool { return d.RevokedAt != nil }

const deviceCols = `device_id, name, token_hash, cert_sha256, cert_pem, enrolled_ms, revoked_ms, last_seen_ms, COALESCE(agent_version, ''), next_token_hash, COALESCE(next_cert_sha256, ''), COALESCE(next_cert_pem, ''), next_issued_ms`

func scanDevice(sc interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	var enrolled int64
	var revoked, seen, issued sql.NullInt64
	if err := sc.Scan(&d.DeviceID, &d.Name, &d.TokenHash, &d.CertSHA256, &d.CertPEM, &enrolled, &revoked, &seen, &d.AgentVersion,
		&d.NextTokenHash, &d.NextCertSHA256, &d.NextCertPEM, &issued); err != nil {
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
	if issued.Valid {
		t := time.UnixMilli(issued.Int64).UTC()
		d.NextIssuedAt = &t
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

// DeviceByTokenHash returns the device owning the token hash, whether it is the current or the pending
// one (ViaPending tells which), revoked or not. Both candidates are compared in constant time.
// It always reads the database, so a revocation or renewal made by the CLI in another process is
// effective on the next request.
func (s *Store) DeviceByTokenHash(ctx context.Context, hash []byte) (*Device, error) {
	d, err := scanDevice(s.r.QueryRowContext(ctx,
		`SELECT `+deviceCols+` FROM devices WHERE token_hash = ?1 OR next_token_hash = ?1`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	cur := subtle.ConstantTimeCompare(hash, d.TokenHash)
	next := subtle.ConstantTimeCompare(hash, d.NextTokenHash)
	if cur|next != 1 {
		return nil, ErrNotFound
	}
	d.ViaPending = next == 1 && cur == 0
	return d, nil
}

// ErrRevoked is returned when an operation is refused because the device is revoked.
var ErrRevoked = errors.New("appareil révoqué")

// SetPendingCredentials stores a new credential pair for a device, replacing any pending one (the current
// pair stays valid). It returns ErrNotFound for an unknown device and ErrRevoked for a revoked one.
func (s *Store) SetPendingCredentials(ctx context.Context, id string, tokenHash []byte, certSHA256, certPEM string, now time.Time) error {
	res, err := s.w.ExecContext(ctx,
		`UPDATE devices SET next_token_hash = ?, next_cert_sha256 = ?, next_cert_pem = ?, next_issued_ms = ?
		 WHERE device_id = ? AND revoked_ms IS NULL`,
		tokenHash, certSHA256, certPEM, now.UnixMilli(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		d, err := s.GetDevice(ctx, id)
		if err != nil {
			return err
		}
		if d.Revoked() {
			return ErrRevoked
		}
		return ErrNotFound
	}
	return nil
}

// PromotePending makes the pending pair the current one, in one statement, if tokenHash is still the
// pending token of a non-revoked device. It reports whether the switch happened (false when a concurrent
// request already did it). The old token and certificate are refused from then on.
func (s *Store) PromotePending(ctx context.Context, id string, tokenHash []byte) (bool, error) {
	res, err := s.w.ExecContext(ctx,
		`UPDATE devices SET token_hash = next_token_hash, cert_sha256 = next_cert_sha256, cert_pem = next_cert_pem,
		   next_token_hash = NULL, next_cert_sha256 = NULL, next_cert_pem = NULL, next_issued_ms = NULL
		 WHERE device_id = ? AND next_token_hash = ? AND revoked_ms IS NULL`, id, tokenHash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
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

// RevokeDevice marks a device revoked and drops any pending renewal (both credential pairs are refused).
// It returns ErrNotFound for unknown devices and leaves an existing revocation date untouched.
func (s *Store) RevokeDevice(ctx context.Context, id string, now time.Time) error {
	res, err := s.w.ExecContext(ctx,
		`UPDATE devices SET revoked_ms = COALESCE(revoked_ms, ?),
		   next_token_hash = NULL, next_cert_sha256 = NULL, next_cert_pem = NULL, next_issued_ms = NULL WHERE device_id = ?`, now.UnixMilli(), id)
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
