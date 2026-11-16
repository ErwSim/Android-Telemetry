package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// addCheapUser stores an account whose hash uses the smallest accepted argon2id
// parameters, so that tests can run many verifications quickly.
func (e *env) addCheapUser(name, password string) {
	e.t.Helper()
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, 1, 8*1024, 1, 32)
	h := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, 8*1024, 1, 1,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	if _, err := e.st.UpsertUser(context.Background(), name, h, time.Now()); err != nil {
		e.t.Fatal(err)
	}
}

// concurrentLogins sends n wrong-password attempts at once and counts the
// password verifications that were actually performed (401 answers).
func (e *env) concurrentLogins(n int, ipOf func(i int) string) (verified, limited int) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := e.login("admin", fmt.Sprintf("wrong-password-%d", i), withRemote(ipOf(i)))
			mu.Lock()
			defer mu.Unlock()
			switch rec.Code {
			case http.StatusUnauthorized:
				verified++
			case http.StatusTooManyRequests:
				limited++
			}
		}()
	}
	close(start)
	wg.Wait()
	return verified, limited
}

// Regression: the login limiters were only checked before the (slow) password
// verification and charged after it, so concurrent attempts all passed the
// check and the "10 failures then 1/min" limit did not hold.
func TestLoginRateLimitHoldsUnderConcurrency(t *testing.T) {
	t.Run("same IP", func(t *testing.T) {
		e := newEnv(t, nil)
		e.addCheapUser("admin", testPassword)
		verified, limited := e.concurrentLogins(60, func(int) string { return "203.0.113.7:4000" })
		if verified > 10 || verified+limited != 60 {
			t.Fatalf("%d password guesses verified (limit 10), %d limited", verified, limited)
		}
	})
	t.Run("same account, many IPs", func(t *testing.T) {
		e := newEnv(t, nil)
		e.addCheapUser("admin", testPassword)
		verified, limited := e.concurrentLogins(60, func(i int) string { return fmt.Sprintf("198.51.100.%d:4000", i+1) })
		if verified > 10 || verified+limited != 60 {
			t.Fatalf("%d password guesses verified (limit 10), %d limited", verified, limited)
		}
	})
	t.Run("successful logins do not lock the user out", func(t *testing.T) {
		e := newEnv(t, nil)
		e.addCheapUser("admin", testPassword)
		for i := range 15 {
			if rec := e.login("admin", testPassword); rec.Code != http.StatusNoContent {
				t.Fatalf("login %d: %d", i, rec.Code)
			}
		}
	})
}

// Regression: per-application byte counts close to the int64 range made the
// SQL SUM() of /stats/top?kind=usage_package fail ("integer overflow", 500).
func TestUsageBytesOverflow(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	now := time.Now().UTC()
	huge := int64(9223372036854775807)
	var evs []map[string]any
	for i := range 3 {
		evs = append(evs, e.event(now.Add(-time.Duration(i)*time.Hour), "net.usage", 0, map[string]any{
			"from": "a", "to": "b", "apps": []any{map[string]any{"package": "p", "rx_bytes": huge, "tx_bytes": huge}}}))
	}
	if r := e.ingest(evs); r.Accepted != 3 {
		t.Fatalf("%+v", r)
	}
	// Second shape: each value fits in int64 but their SQL sum does not.
	evs = nil
	for i := range 3 {
		evs = append(evs, e.event(now.Add(-time.Duration(i)*time.Hour), "net.usage", 0, map[string]any{
			"from": "a", "to": "b", "apps": []any{map[string]any{"package": "p", "rx_bytes": int64(1) << 62}}}))
	}
	if r := e.ingest(evs); r.Accepted != 3 {
		t.Fatalf("%+v", r)
	}
	rec := e.get(c, "/api/console/stats/top", url.Values{"kind": {"usage_package"},
		"from": {now.Add(-24 * time.Hour).Format(time.RFC3339)}, "to": {now.Add(time.Hour).Format(time.RFC3339)}})
	if rec.Code != http.StatusOK {
		t.Fatalf("top usage_package: %d %s", rec.Code, rec.Body)
	}
	items := decodeJSON[struct {
		Items []struct {
			Key   string `json:"key"`
			Bytes int64  `json:"bytes"`
		} `json:"items"`
	}](t, rec).Items
	if len(items) != 1 || items[0].Bytes <= 0 {
		t.Fatalf("items: %+v", items)
	}
}

// Regression: the retention purge kept the last position, heartbeat and posture
// of each device forever (device_latest), beyond WATCHPOST_RETENTION_DAYS.
func TestRetentionPurgesLatestState(t *testing.T) {
	e := newEnv(t, nil)
	c := e.session()
	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)
	if r := e.ingest([]map[string]any{
		e.event(old, "location.fix", 0, map[string]any{"lat": 48.85, "lon": 2.35}),
		e.event(old, "agent.heartbeat", 0, map[string]any{"battery_pct": 50}),
		e.event(old, "security.posture", 0, map[string]any{"adb_enabled": false}),
	}); r.Accepted != 3 {
		t.Fatalf("%+v", r)
	}
	if _, err := e.st.Purge(context.Background(), now.Add(-90*24*time.Hour), now, sessionIdle); err != nil {
		t.Fatal(err)
	}
	devs := decodeJSON[struct {
		Devices []map[string]any `json:"devices"`
	}](t, e.get(c, "/api/console/devices", nil)).Devices
	if len(devs) != 1 {
		t.Fatalf("devices: %+v", devs)
	}
	for _, k := range []string{"last_location", "last_heartbeat", "last_posture"} {
		if v, ok := devs[0][k]; ok {
			t.Errorf("%s survived the retention purge: %v", k, v)
		}
	}
}
