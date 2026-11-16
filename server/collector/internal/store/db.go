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
	// retention is the retention window; events whose ts is older are acknowledged but not stored.
	// Zero disables the check. Set once before serving (SetRetention).
	retention time.Duration
}

// SetRetention sets the retention window used by Ingest to drop events older than it.
// It must be called before the store is shared between goroutines.
func (s *Store) SetRetention(d time.Duration) { s.retention = d }

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
		return nil, fmt.Errorf("creating the data directory: %w", err)
	}
	if err := restrictFiles(path); err != nil {
		return nil, err
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

// restrictFiles makes the database file (created empty if needed) and any
// leftover -wal/-shm/-journal files private to the service account before SQLite opens
// them. SQLite creates its WAL and shared-memory files with the mode of the
// database file, so creating the database 0600 first keeps the WAL, which holds
// the most recent events, from being readable by other local users.
func restrictFiles(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("opening the database: %w", err)
	}
	f.Close()
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if st, err := os.Stat(p); err == nil && st.Mode().Perm()&0o077 != 0 {
			// Best effort: a CLI run by another user may not own the files.
			_ = os.Chmod(p, st.Mode().Perm()&0o700)
		}
	}
	return nil
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
	// 3: /stats/top weights net.dns and net.connect by data.count (integer in [1, 1000000], else 1), so the
	// four net.* kinds are rebuilt from events. Same rule as eventWeight in ingest.go. Hours are keyed on ts.
	`
DELETE FROM top_counts WHERE kind IN ('dns_hostname', 'dns_package', 'connect_dest', 'connect_package');

INSERT INTO top_counts
SELECT 'dns_hostname', h, device_id, pkg, k, SUM(w), 0 FROM (
	SELECT ts_ms - ts_ms % 3600000 AS h, device_id,
		COALESCE(CASE WHEN json_type(data, '$.package') = 'text' THEN substr(json_extract(data, '$.package'), 1, 255) END, '') AS pkg,
		substr(lower(rtrim(json_extract(data, '$.hostname'), '.')), 1, 255) AS k,
		CASE WHEN json_type(data, '$.count') = 'integer' AND json_extract(data, '$.count') BETWEEN 1 AND 1000000
			THEN json_extract(data, '$.count') ELSE 1 END AS w
	FROM events WHERE type = 'net.dns' AND json_type(data, '$.hostname') = 'text' AND json_extract(data, '$.hostname') <> '')
GROUP BY h, device_id, pkg, k;

INSERT INTO top_counts
SELECT kind, h, device_id, pkg, pkg, SUM(w), 0 FROM (
	SELECT CASE type WHEN 'net.dns' THEN 'dns_package' ELSE 'connect_package' END AS kind,
		ts_ms - ts_ms % 3600000 AS h, device_id, substr(json_extract(data, '$.package'), 1, 255) AS pkg,
		CASE WHEN json_type(data, '$.count') = 'integer' AND json_extract(data, '$.count') BETWEEN 1 AND 1000000
			THEN json_extract(data, '$.count') ELSE 1 END AS w
	FROM events
	WHERE type IN ('net.dns', 'net.connect') AND json_type(data, '$.package') = 'text' AND json_extract(data, '$.package') <> '')
GROUP BY kind, h, device_id, pkg;

INSERT INTO top_counts
SELECT 'connect_dest', h, device_id, pkg, k, SUM(w), 0 FROM (
	SELECT ts_ms - ts_ms % 3600000 AS h, device_id,
		COALESCE(CASE WHEN json_type(data, '$.package') = 'text' THEN substr(json_extract(data, '$.package'), 1, 255) END, '') AS pkg,
		CASE WHEN json_type(data, '$.port') = 'integer' THEN
			CASE WHEN instr(json_extract(data, '$.ip'), ':') > 0
				THEN '[' || substr(json_extract(data, '$.ip'), 1, 64) || ']:' || json_extract(data, '$.port')
				ELSE substr(json_extract(data, '$.ip'), 1, 64) || ':' || json_extract(data, '$.port') END
		ELSE substr(json_extract(data, '$.ip'), 1, 64) END AS k,
		CASE WHEN json_type(data, '$.count') = 'integer' AND json_extract(data, '$.count') BETWEEN 1 AND 1000000
			THEN json_extract(data, '$.count') ELSE 1 END AS w
	FROM events WHERE type = 'net.connect' AND json_type(data, '$.ip') = 'text' AND json_extract(data, '$.ip') <> '')
GROUP BY h, device_id, pkg, k;
`,
	// 4: certificate/token renewal (contract §4). A renewed device keeps its device_id and carries a second,
	// pending credential pair; the first authenticated request with the pending pair makes it current.
	// The pair is always used as a whole: token and certificate fingerprint of the same generation.
	`
ALTER TABLE devices ADD COLUMN next_token_hash BLOB;
ALTER TABLE devices ADD COLUMN next_cert_sha256 TEXT;
ALTER TABLE devices ADD COLUMN next_cert_pem TEXT;
ALTER TABLE devices ADD COLUMN next_issued_ms INTEGER;
CREATE UNIQUE INDEX devices_next_token ON devices(next_token_hash) WHERE next_token_hash IS NOT NULL;
`,
	// 5: remote commands (contract §8), events produced by the collector itself (source = 'server'),
	// command channel state of each device, and the aggregates of the tracking view (§9): AdGuard Home
	// query log per hour and domain, and per-application byte counters (rx and tx kept apart).
	`
CREATE TABLE commands (
	id           TEXT PRIMARY KEY,
	device_id    TEXT NOT NULL REFERENCES devices(device_id),
	type         TEXT NOT NULL,
	params       TEXT NOT NULL,
	payload      TEXT NOT NULL,
	sig          TEXT,
	status       TEXT NOT NULL,
	created_ms   INTEGER NOT NULL,
	created_by   TEXT NOT NULL,
	issued_ms    INTEGER NOT NULL,
	expires_ms   INTEGER NOT NULL,
	delivered_ms INTEGER,
	attempts     INTEGER NOT NULL DEFAULT 0,
	result_ms    INTEGER,
	agent_at_ms  INTEGER,
	detail       TEXT
);
CREATE INDEX commands_dev_created ON commands(device_id, created_ms);
CREATE INDEX commands_open ON commands(device_id, created_ms) WHERE status IN ('pending', 'delivered');
CREATE INDEX commands_expiry ON commands(expires_ms) WHERE status IN ('pending', 'delivered');

ALTER TABLE events ADD COLUMN source TEXT;
ALTER TABLE devices ADD COLUMN cmd_mode TEXT;
ALTER TABLE devices ADD COLUMN cmd_contact_ms INTEGER;

CREATE TABLE tracking_counts (
	hour_ms INTEGER NOT NULL,
	client  TEXT NOT NULL,
	domain  TEXT NOT NULL,
	queries INTEGER NOT NULL,
	blocked INTEGER NOT NULL,
	reason  TEXT NOT NULL,
	PRIMARY KEY (hour_ms, client, domain)
) WITHOUT ROWID;

CREATE TABLE usage_counts (
	hour_ms   INTEGER NOT NULL,
	device_id TEXT NOT NULL,
	package   TEXT NOT NULL,
	rx_bytes  INTEGER NOT NULL,
	tx_bytes  INTEGER NOT NULL,
	PRIMARY KEY (hour_ms, device_id, package)
) WITHOUT ROWID;

INSERT INTO usage_counts
SELECT h, device_id, pkg, min(SUM(rx), 9007199254740991), min(SUM(tx), 9007199254740991) FROM (
	SELECT e.ts_ms - e.ts_ms % 3600000 AS h, e.device_id, substr(json_extract(a.value, '$.package'), 1, 255) AS pkg,
		min(max(COALESCE(CASE WHEN json_type(a.value, '$.rx_bytes') = 'integer' THEN json_extract(a.value, '$.rx_bytes') END, 0), 0), 9007199254740991) AS rx,
		min(max(COALESCE(CASE WHEN json_type(a.value, '$.tx_bytes') = 'integer' THEN json_extract(a.value, '$.tx_bytes') END, 0), 0), 9007199254740991) AS tx
	FROM events e, json_each(e.data, '$.apps') a
	WHERE e.type = 'net.usage' AND a.type = 'object' AND json_type(a.value, '$.package') = 'text' AND json_extract(a.value, '$.package') <> '')
GROUP BY h, device_id, pkg;
`,
	// 6: behavioral detections (contract §11.3). AdGuard Home blocks due to a threat list are counted apart
	// (tracking_counts.threat); app.ops is aggregated per hour, application and operation; the latest app.risk
	// of each application and the latest app.role of each role are kept; detections are stored once per
	// device, type, subject and window; detect_dirty lists the hours whose aggregates changed since the
	// detections last looked at them (late batches included). Rebuilt from the stored events, reading them
	// per device through the (device_id, type, ts_ms) index; the hours of the last two days already stored
	// are marked for a first evaluation.
	`
ALTER TABLE tracking_counts ADD COLUMN threat INTEGER NOT NULL DEFAULT 0;

CREATE TABLE ops_counts (
	device_id TEXT NOT NULL,
	hour_ms   INTEGER NOT NULL,
	package   TEXT NOT NULL,
	op        TEXT NOT NULL,
	count     INTEGER NOT NULL,
	bg_count  INTEGER NOT NULL,
	last_ms   INTEGER,
	PRIMARY KEY (device_id, hour_ms, package, op)
) WITHOUT ROWID;

INSERT INTO ops_counts(device_id, hour_ms, package, op, count, bg_count, last_ms)
SELECT device_id, h, pkg, op, min(SUM(c), 9007199254740991), min(SUM(b), 9007199254740991), MAX(l) FROM (
	SELECT e.device_id, e.ts_ms - (e.ts_ms % 3600000) AS h,
		substr(json_extract(a.value, '$.package'), 1, 255) AS pkg, substr(json_extract(a.value, '$.op'), 1, 32) AS op,
		min(max(COALESCE(CASE WHEN json_type(a.value, '$.count') = 'integer' THEN json_extract(a.value, '$.count') END, 0), 0), 1000000000) AS c,
		min(max(COALESCE(CASE WHEN json_type(a.value, '$.background_count') = 'integer' THEN json_extract(a.value, '$.background_count') END, 0), 0), 1000000000) AS b,
		CASE WHEN json_type(a.value, '$.last_ts') = 'text' THEN CAST((julianday(json_extract(a.value, '$.last_ts')) - 2440587.5) * 86400000 AS INTEGER) END AS l
	FROM devices d JOIN events e INDEXED BY events_dev_type_ts ON e.device_id = d.device_id AND e.type = 'app.ops',
		json_each(e.data, '$.apps') a
	WHERE a.type = 'object' AND json_type(a.value, '$.package') = 'text' AND json_extract(a.value, '$.package') <> ''
		AND json_type(a.value, '$.op') = 'text' AND json_extract(a.value, '$.op') <> '')
GROUP BY device_id, h, pkg, op;

CREATE TABLE app_latest (
	device_id TEXT NOT NULL,
	kind      TEXT NOT NULL,
	key       TEXT NOT NULL,
	ts_ms     INTEGER NOT NULL,
	data      TEXT NOT NULL,
	PRIMARY KEY (device_id, kind, key)
) WITHOUT ROWID;

INSERT INTO app_latest(device_id, kind, key, ts_ms, data)
SELECT device_id, kind, k, ts_ms, data FROM (
	SELECT e.device_id, CASE e.type WHEN 'app.risk' THEN 'risk' ELSE 'role' END AS kind,
		substr(json_extract(e.data, CASE e.type WHEN 'app.risk' THEN '$.package' ELSE '$.role' END), 1, 255) AS k,
		e.ts_ms, e.data,
		ROW_NUMBER() OVER (PARTITION BY e.device_id, e.type, json_extract(e.data, CASE e.type WHEN 'app.risk' THEN '$.package' ELSE '$.role' END)
			ORDER BY e.ts_ms DESC, e.pk DESC) AS rn
	FROM devices d JOIN events e INDEXED BY events_dev_type_ts ON e.device_id = d.device_id AND e.type IN ('app.risk', 'app.role')
	WHERE json_type(e.data, CASE e.type WHEN 'app.risk' THEN '$.package' ELSE '$.role' END) = 'text')
WHERE rn = 1 AND k <> '';

CREATE TABLE detections (
	pk             INTEGER PRIMARY KEY AUTOINCREMENT,
	id             TEXT NOT NULL UNIQUE,
	device_id      TEXT NOT NULL,
	type           TEXT NOT NULL,
	subject        TEXT NOT NULL,
	window_from_ms INTEGER NOT NULL,
	window_to_ms   INTEGER NOT NULL,
	ts_ms          INTEGER NOT NULL,
	package        TEXT NOT NULL,
	label          TEXT NOT NULL,
	sev            INTEGER NOT NULL,
	summary        TEXT NOT NULL,
	evidence       TEXT NOT NULL,
	UNIQUE (device_id, type, subject, window_from_ms)
);
CREATE INDEX detections_ts ON detections(ts_ms);
CREATE INDEX detections_dev_ts ON detections(device_id, ts_ms);

CREATE TABLE detect_dirty (
	device_id TEXT NOT NULL,
	hour_ms   INTEGER NOT NULL,
	gen       INTEGER NOT NULL,
	PRIMARY KEY (device_id, hour_ms)
) WITHOUT ROWID;

INSERT OR IGNORE INTO detect_dirty(device_id, hour_ms, gen)
SELECT device_id, hour_ms, 0 FROM event_counts
WHERE hour_ms >= (SELECT COALESCE(MAX(hour_ms), 0) FROM event_counts) - 172800000
	AND type IN ('net.dns', 'net.connect', 'net.usage', 'app.ops', 'app.risk', 'app.installed', 'app.permission_changed',
		'app.special_access', 'app.role')
GROUP BY device_id, hour_ms;
`,
	// 7: app.ops carries rejected_count (contract §11.2: accesses refused by the system, e.g. by a guard of the
	// agent): ops_counts keeps it, rebuilt from the events like in migration 6.
	`
ALTER TABLE ops_counts ADD COLUMN rej_count INTEGER NOT NULL DEFAULT 0;
DELETE FROM ops_counts;
INSERT INTO ops_counts(device_id, hour_ms, package, op, count, bg_count, rej_count, last_ms)
SELECT device_id, h, pkg, op, min(SUM(c), 9007199254740991), min(SUM(b), 9007199254740991), min(SUM(r), 9007199254740991), MAX(l) FROM (
	SELECT e.device_id, e.ts_ms - (e.ts_ms % 3600000) AS h,
		substr(json_extract(a.value, '$.package'), 1, 255) AS pkg, substr(json_extract(a.value, '$.op'), 1, 32) AS op,
		min(max(COALESCE(CASE WHEN json_type(a.value, '$.count') = 'integer' THEN json_extract(a.value, '$.count') END, 0), 0), 1000000000) AS c,
		min(max(COALESCE(CASE WHEN json_type(a.value, '$.background_count') = 'integer' THEN json_extract(a.value, '$.background_count') END, 0), 0), 1000000000) AS b,
		min(max(COALESCE(CASE WHEN json_type(a.value, '$.rejected_count') = 'integer' THEN json_extract(a.value, '$.rejected_count') END, 0), 0), 1000000000) AS r,
		CASE WHEN json_type(a.value, '$.last_ts') = 'text' THEN CAST((julianday(json_extract(a.value, '$.last_ts')) - 2440587.5) * 86400000 AS INTEGER) END AS l
	FROM devices d JOIN events e INDEXED BY events_dev_type_ts ON e.device_id = d.device_id AND e.type = 'app.ops',
		json_each(e.data, '$.apps') a
	WHERE a.type = 'object' AND json_type(a.value, '$.package') = 'text' AND json_extract(a.value, '$.package') <> ''
		AND json_type(a.value, '$.op') = 'text' AND json_extract(a.value, '$.op') <> '')
GROUP BY device_id, h, pkg, op;
`,
	// 8: one detection per application and window, updated in place when the window brings more (contract
	// §11.3, grouping asked by the console): its elements (domains, capabilities…), the time of the last update,
	// and what was last exported to Wazuh (an update is exported again only when it is more severe or brings a
	// new element, at most once an hour).
	`
ALTER TABLE detections ADD COLUMN items TEXT NOT NULL DEFAULT '[]';
ALTER TABLE detections ADD COLUMN updated_ms INTEGER;
ALTER TABLE detections ADD COLUMN exported_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detections ADD COLUMN exported_sev INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detections ADD COLUMN exported_items TEXT NOT NULL DEFAULT '[]';
UPDATE detections SET exported_ms = ts_ms, exported_sev = sev;
`,
	// 9: review of v1.2 (contract §11.4): muted detections (computed and stored, neither exported nor streamed),
	// recurring ones (severity capped at 1), and the mutes set from the console.
	`
ALTER TABLE detections ADD COLUMN muted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detections ADD COLUMN recurring INTEGER NOT NULL DEFAULT 0;
CREATE TABLE detect_mutes (
	device_id  TEXT NOT NULL,
	type       TEXT NOT NULL,
	package    TEXT NOT NULL,
	reason     TEXT NOT NULL,
	created_ms INTEGER NOT NULL,
	created_by TEXT NOT NULL,
	PRIMARY KEY (device_id, type, package)
) WITHOUT ROWID;
`,
}

// SchemaVersion is the schema version this binary expects.
var SchemaVersion = len(migrations)

func (s *Store) migrate(ctx context.Context) error {
	conn, err := s.w.Conn(ctx)
	if err != nil {
		return fmt.Errorf("opening the database: %w", err)
	}
	defer conn.Close()
	var v int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("reading the schema version: %w", err)
	}
	if v > len(migrations) {
		return fmt.Errorf("database schema at version %d, newer than this binary (%d)", v, len(migrations))
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
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
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
