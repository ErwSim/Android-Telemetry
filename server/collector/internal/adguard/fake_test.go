package adguard

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

// The fake answers "older_than" like AdGuard Home v0.107.80 does (observed on a real instance with
// querylog.size_memory: 1, single file then after a rotation; see internal/querylog in its sources): the
// tests of the collector are only worth something if this behaviour is the real one.
func TestFakeQueryLogSeeksLikeAdGuardHome(t *testing.T) {
	f := NewFake("", "")
	srv := httptest.NewServer(f)
	defer srv.Close()
	c, err := New(srv.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return base.Add(time.Duration(i) * time.Second) }
	for i := range 40 {
		f.AddQuery(at(i), "192.0.2.1", "phone", "a.example")
	}
	count := func(older time.Time) (int, string) {
		t.Helper()
		v := ""
		if !older.IsZero() {
			v = older.Format(time.RFC3339Nano)
		}
		p, err := c.QueryLog(context.Background(), v, 500)
		if err != nil {
			t.Fatal(err)
		}
		newest := ""
		if len(p.Data) > 0 {
			newest = p.Data[0].Time
		}
		return len(p.Data), newest
	}
	check := func(what string, older time.Time, want int, wantNewest time.Time) {
		t.Helper()
		n, newest := count(older)
		wn := ""
		if want > 0 {
			wn = wantNewest.Format(time.RFC3339Nano)
		}
		if n != want || newest != wn {
			t.Errorf("%s: %d entries from %q, want %d from %q", what, n, newest, want, wn)
		}
	}
	// One file.
	check("no older_than", time.Time{}, 40, at(39))
	check("exact time of a record", at(30), 30, at(29))
	check("exact time of the newest record", at(39), 39, at(38))
	check("between two records: nothing", at(30).Add(time.Millisecond), 0, time.Time{})
	check("later than every record: the newest one is skipped", at(100), 39, at(38))
	check("exact time of the oldest record", at(0), 0, time.Time{})
	check("earlier than every record", at(-10), 0, time.Time{})
	// After a rotation: records 0..39 are in the rotated file, 40..54 in the current one.
	f.Rotate()
	for i := 40; i < 55; i++ {
		f.AddQuery(at(i), "192.0.2.1", "phone", "a.example")
	}
	check("two files, no older_than", time.Time{}, 55, at(54))
	check("two files, later than every record", at(100), 54, at(53))
	check("exact, current file", at(50), 50, at(49))
	check("exact, oldest of the current file", at(40), 40, at(39))
	check("exact, rotated file", at(30), 30, at(29))
	check("between the two files: found", at(39).Add(time.Millisecond), 40, at(39))
	check("between two records of the current file: nothing", at(50).Add(time.Millisecond), 0, time.Time{})
	check("between two records of the rotated file: nothing", at(30).Add(time.Millisecond), 0, time.Time{})
	// A second rotation deletes the first file.
	f.Rotate()
	check("after a second rotation", time.Time{}, 15, at(54))
	check("cursor of a deleted record", at(30), 0, time.Time{})
	// Records still in memory (size_memory > 1; here 50..54, the file holds 40..49) are filtered by time,
	// whatever older_than is; a time later than the file skips the newest record of the file (49).
	f.SetMemory(5)
	check("memory: between two records in memory", at(52).Add(time.Millisecond), 3+9, at(52))
	check("memory: exact record in memory", at(52), 2+9, at(51))
	check("memory: exact record of the file", at(45), 5, at(44))
}
