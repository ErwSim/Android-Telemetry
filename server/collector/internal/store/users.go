package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// User is a console account.
type User struct {
	Username     string
	PasswordHash string
}

// UpsertUser creates or updates a console account. Updating a password
// invalidates the user's existing sessions.
func (s *Store) UpsertUser(ctx context.Context, username, hash string, now time.Time) (created bool, err error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE username = ?`, username).Scan(&exists)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		created = true
		_, err = tx.ExecContext(ctx, `INSERT INTO users(username, password_hash, created_ms, updated_ms) VALUES(?,?,?,?)`,
			username, hash, now.UnixMilli(), now.UnixMilli())
	case err == nil:
		_, err = tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, updated_ms = ? WHERE username = ?`, hash, now.UnixMilli(), username)
		if err == nil {
			_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE username = ?`, username)
		}
	}
	if err != nil {
		return false, err
	}
	return created, tx.Commit()
}

// GetUser returns an account.
func (s *Store) GetUser(ctx context.Context, username string) (*User, error) {
	var u User
	err := s.r.QueryRowContext(ctx, `SELECT username, password_hash FROM users WHERE username = ?`, username).Scan(&u.Username, &u.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

// CountUsers returns the number of console accounts.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// Session is a console session.
type Session struct {
	Username string
	LastSeen time.Time
	Expires  time.Time
}

// CreateSession stores a session identified by the hash of its token.
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, username string, now, expires time.Time) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO sessions(token_hash, username, created_ms, last_seen_ms, expires_ms) VALUES(?,?,?,?,?)`,
		tokenHash, username, now.UnixMilli(), now.UnixMilli(), expires.UnixMilli())
	return err
}

// GetSession returns a session that has not expired.
func (s *Store) GetSession(ctx context.Context, tokenHash []byte, now time.Time) (*Session, error) {
	var ss Session
	var seen, exp int64
	err := s.r.QueryRowContext(ctx, `SELECT username, last_seen_ms, expires_ms FROM sessions WHERE token_hash = ? AND expires_ms > ?`,
		tokenHash, now.UnixMilli()).Scan(&ss.Username, &seen, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ss.LastSeen = time.UnixMilli(seen)
	ss.Expires = time.UnixMilli(exp)
	return &ss, nil
}

// TouchSession updates the last activity time of a session.
func (s *Store) TouchSession(ctx context.Context, tokenHash []byte, now time.Time) error {
	_, err := s.w.ExecContext(ctx, `UPDATE sessions SET last_seen_ms = ? WHERE token_hash = ?`, now.UnixMilli(), tokenHash)
	return err
}

// DeleteSession removes a session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}
