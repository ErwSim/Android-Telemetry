package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Regression: on first start the WAL and shared-memory files (recent events,
// i.e. positions) were created 0644, readable by every local user when the
// data directory itself is not private (bind mount, development directory).
func TestDatabaseFilesArePrivate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "watchpost.db")
	// A leftover WAL from an older version, world-readable.
	if err := os.WriteFile(path+"-wal", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path+"-wal", 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetKV(context.Background(), "k", "v"); err != nil {
		t.Fatal(err)
	}
	var one int
	if err := st.r.QueryRow("SELECT 1").Scan(&one); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"watchpost.db", "watchpost.db-wal", "watchpost.db-shm"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %v", f, fi.Mode().Perm())
		}
	}
}
