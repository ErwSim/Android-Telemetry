// Package store implements the SQLite storage of the collector.
//
// Two connection pools are used: a single-connection writer (transactions start
// with BEGIN IMMEDIATE, so concurrent writers never deadlock on lock upgrades)
// and a small read-only pool. The database runs in WAL mode so that readers never
// block the writer. Other processes (CLI sub-commands) may open the same file
// concurrently; busy_timeout serializes them.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure Go SQLite driver
)

// Store wraps the database handles.
type Store struct {
	w    *sql.DB // writer, one connection
	r    *sql.DB // readers
	path string
}

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("introuvable")

func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	// FULL: an event acknowledged to the agent (which then deletes it) must survive a power loss.
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "temp_store(MEMORY)")
	q.Add("_pragma", "cache_size(-16000)")
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Set("_txlock", "immediate")
	}
	return "file:" + filepath.ToSlash(path) + "?" + q.Encode()
}

// Open opens (and creates or migrates) the database at path.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("création du répertoire de données : %w", err)
	}
	w, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)
	s := &Store{w: w, path: path}
	if err := s.migrate(ctx); err != nil {
		w.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	r, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(8)
	r.SetMaxIdleConns(4)
	r.SetConnMaxIdleTime(5 * time.Minute)
	s.r = r
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error {
	var err error
	if s.r != nil {
		err = s.r.Close()
	}
	if e := s.w.Close(); e != nil && err == nil {
		err = e
	}
	return err
}

// Ping checks that the database answers.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.r.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

// migrations are applied in order; PRAGMA user_version stores the applied count.
var migrations = []string{
	// 1: initial schema
	`
CREATE TABLE devices (
	device_id     TEXT PRIMARY KEY,
	name          TEXT NOT NULL,
	token_hash    BLOB NOT NULL UNIQUE,
	cert_sha256   TEXT NOT NULL,
	cert_pem      TEXT NOT NULL,
	enrolled_ms   INTEGER NOT NULL,
	revoked_ms    INTEGER,
	last_seen_ms  INTEGER,
	agent_version TEXT
);

CREATE TABLE events (
	pk          INTEGER PRIMARY KEY AUTOINCREMENT,
	id          TEXT NOT NULL UNIQUE,
	device_id   TEXT NOT NULL,
	ts_ms       INTEGER NOT NULL,
	received_ms INTEGER NOT NULL,
	seq         INTEGER NOT NULL,
	boot_id     TEXT NOT NULL,
	elapsed_ms  INTEGER NOT NULL,
	type        TEXT NOT NULL,
	sev         INTEGER NOT NULL,
	data        TEXT NOT NULL
);
CREATE INDEX events_dev_ts ON events(device_id, ts_ms);
CREATE INDEX events_dev_type_ts ON events(device_id, type, ts_ms);
CREATE INDEX events_dev_sev_ts ON events(device_id, sev, ts_ms) WHERE sev > 0;

CREATE TABLE event_types (
	device_id TEXT NOT NULL,
	type      TEXT NOT NULL,
	PRIMARY KEY (device_id, type)
) WITHOUT ROWID;

CREATE TABLE locations (
	event_pk  INTEGER PRIMARY KEY,
	device_id TEXT NOT NULL,
	ts_ms     INTEGER NOT NULL,
	lat       REAL NOT NULL,
	lon       REAL NOT NULL,
	acc_m     REAL,
	speed_mps REAL,
	provider  TEXT,
	mock      INTEGER
);
CREATE INDEX locations_dev_ts ON locations(device_id, ts_ms);

CREATE TABLE device_latest (
	device_id TEXT NOT NULL,
	kind      TEXT NOT NULL,
	ts_ms     INTEGER NOT NULL,
	data      TEXT NOT NULL,
	PRIMARY KEY (device_id, kind)
) WITHOUT ROWID;

CREATE TABLE event_counts (
	hour_ms   INTEGER NOT NULL,
	device_id TEXT NOT NULL,
	type      TEXT NOT NULL,
	sev       INTEGER NOT NULL,
	count     INTEGER NOT NULL,
	PRIMARY KEY (hour_ms, device_id, type, sev)
) WITHOUT ROWID;

CREATE TABLE top_counts (
	kind      TEXT NOT NULL,
	hour_ms   INTEGER NOT NULL,
	device_id TEXT NOT NULL,
	key       TEXT NOT NULL,
	count     INTEGER NOT NULL,
	bytes     INTEGER NOT NULL,
	PRIMARY KEY (kind, hour_ms, device_id, key)
) WITHOUT ROWID;

CREATE TABLE users (
	username      TEXT PRIMARY KEY,
	password_hash TEXT NOT NULL,
	created_ms    INTEGER NOT NULL,
	updated_ms    INTEGER NOT NULL
);

CREATE TABLE sessions (
	token_hash   BLOB PRIMARY KEY,
	username     TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
	created_ms   INTEGER NOT NULL,
	last_seen_ms INTEGER NOT NULL,
	expires_ms   INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(username);

CREATE TABLE kv (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`,
	// 2: top_counts gains a package dimension (/stats/top?package=), rebuilt from events.
	`
DROP TABLE top_counts;
CREATE TABLE top_counts (
	kind      TEXT NOT NULL,
	hour_ms   INTEGER NOT NULL,
	device_id TEXT NOT NULL,
	package   TEXT NOT NULL,
	key       TEXT NOT NULL,
	count     INTEGER NOT NULL,
	bytes     INTEGER NOT NULL,
	PRIMARY KEY (kind, hour_ms, device_id, package, key)
) WITHOUT ROWID;

INSERT INTO top_counts
SELECT 'dns_hostname', h, device_id, pkg, k, COUNT(*), 0 FROM (
	SELECT ts_ms - ts_ms % 3600000 AS h, device_id,
		COALESCE(CASE WHEN json_type(data, '$.package') = 'text' THEN substr(json_extract(data, '$.package'), 1, 255) END, '') AS pkg,
		substr(lower(rtrim(json_extract(data, '$.hostname'), '.')), 1, 255) AS k
	FROM events WHERE type = 'net.dns' AND json_type(data, '$.hostname') = 'text' AND json_extract(data, '$.hostname') <> '')
GROUP BY h, device_id, pkg, k;

INSERT INTO top_counts
SELECT kind, h, device_id, pkg, pkg, COUNT(*), 0 FROM (
	SELECT CASE type WHEN 'net.dns' THEN 'dns_package' WHEN 'net.connect' THEN 'connect_package'
		WHEN 'app.foreground' THEN 'foreground_package' ELSE 'notification_package' END AS kind,
		ts_ms - ts_ms % 3600000 AS h, device_id, substr(json_extract(data, '$.package'), 1, 255) AS pkg
	FROM events
	WHERE json_type(data, '$.package') = 'text' AND json_extract(data, '$.package') <> '' AND (
		type IN ('net.dns', 'net.connect')
		OR (type = 'app.foreground' AND json_extract(data, '$.event') = 'resumed')
		OR (type = 'app.notification' AND json_extract(data, '$.event') = 'posted')))
GROUP BY kind, h, device_id, pkg;

INSERT INTO top_counts
SELECT 'connect_dest', h, device_id, pkg, k, COUNT(*), 0 FROM (
	SELECT ts_ms - ts_ms % 3600000 AS h, device_id,
		COALESCE(CASE WHEN json_type(data, '$.package') = 'text' THEN substr(json_extract(data, '$.package'), 1, 255) END, '') AS pkg,
		CASE WHEN json_type(data, '$.port') = 'integer' THEN
			CASE WHEN instr(json_extract(data, '$.ip'), ':') > 0
				THEN '[' || substr(json_extract(data, '$.ip'), 1, 64) || ']:' || json_extract(data, '$.port')
				ELSE substr(json_extract(data, '$.ip'), 1, 64) || ':' || json_extract(data, '$.port') END
		ELSE substr(json_extract(data, '$.ip'), 1, 64) END AS k
	FROM events WHERE type = 'net.connect' AND json_type(data, '$.ip') = 'text' AND json_extract(data, '$.ip') <> '')
GROUP BY h, device_id, pkg, k;

INSERT INTO top_counts
SELECT 'usage_package', h, device_id, pkg, pkg, COUNT(*), SUM(b) FROM (
	SELECT e.ts_ms - e.ts_ms % 3600000 AS h, e.device_id, substr(json_extract(a.value, '$.package'), 1, 255) AS pkg,
		max(COALESCE(CASE WHEN json_type(a.value, '$.rx_bytes') = 'integer' THEN json_extract(a.value, '$.rx_bytes') END, 0), 0) +
		max(COALESCE(CASE WHEN json_type(a.value, '$.tx_bytes') = 'integer' THEN json_extract(a.value, '$.tx_bytes') END, 0), 0) AS b
	FROM events e, json_each(e.data, '$.apps') a
	WHERE e.type = 'net.usage' AND a.type = 'object' AND json_type(a.value, '$.package') = 'text' AND json_extract(a.value, '$.package') <> '')
GROUP BY h, device_id, pkg;
`,
}

// SchemaVersion is the schema version this binary expects.
var SchemaVersion = len(migrations)

func (s *Store) migrate(ctx context.Context) error {
	conn, err := s.w.Conn(ctx)
	if err != nil {
		return fmt.Errorf("ouverture de la base : %w", err)
	}
	defer conn.Close()
	var v int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("lecture de la version du schéma : %w", err)
	}
	if v > len(migrations) {
		return fmt.Errorf("schéma de base en version %d, plus récent que ce binaire (%d)", v, len(migrations))
	}
	if v == 0 {
		// Must be set before the first table is created; lets the purge give space back.
		if _, err := conn.ExecContext(ctx, "PRAGMA auto_vacuum = INCREMENTAL"); err != nil {
			return err
		}
	}
	for i := v; i < len(migrations); i++ {
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d : %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration %d : %w", i+1, err)
		}
	}
	return nil
}

// GetKV reads a value from the kv table.
func (s *Store) GetKV(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.w.QueryRowContext(ctx, "SELECT value FROM kv WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

// SetKV writes a value into the kv table.
func (s *Store) SetKV(ctx context.Context, key, value string) error {
	_, err := s.w.ExecContext(ctx,
		"INSERT INTO kv(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
	return err
}

func nullInt(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	x := v.Int64
	return &x
}
