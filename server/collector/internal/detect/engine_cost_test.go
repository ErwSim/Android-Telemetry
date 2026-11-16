package detect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/model"
	"github.com/erwsim/watchpost/server/collector/internal/sim"
	"github.com/erwsim/watchpost/server/collector/internal/store"
)

// TestDetectionCost measures the detection job on a database of a few million simulated events (89 days of
// a phone, every attack scenario in the last two days): full evaluation of the backlog, steady state after
// a late batch, and the latency of the ingestion while the job runs. Long: only with
// WATCHPOST_DETECT_COST=<days> (e.g. 89), optionally WATCHPOST_DETECT_COST_RATE (default 2) and
// WATCHPOST_DETECT_COST_DB (database path kept between runs).
func TestDetectionCost(t *testing.T) {
	days, _ := strconv.Atoi(os.Getenv("WATCHPOST_DETECT_COST"))
	if days <= 0 {
		t.Skip("WATCHPOST_DETECT_COST=<days> to measure the cost of the detections")
	}
	rate := 2.0
	if v, err := strconv.ParseFloat(os.Getenv("WATCHPOST_DETECT_COST_RATE"), 64); err == nil && v > 0 {
		rate = v
	}
	ctx := context.Background()
	path := os.Getenv("WATCHPOST_DETECT_COST_DB")
	if path == "" {
		path = filepath.Join(t.TempDir(), "cost.db")
	}
	_, statErr := os.Stat(path)
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetRetention(90 * 24 * time.Hour)
	const dev = "dev_cost"
	now := time.Now().UTC()
	if os.IsNotExist(statErr) {
		if err := st.CreateDevice(ctx, &store.Device{DeviceID: dev, Name: "phone", TokenHash: []byte("x"), CertSHA256: "x", CertPEM: "x", EnrolledAt: now}); err != nil {
			t.Fatal(err)
		}
		all, _ := sim.ParseScenarios(sim.ScenarioAll)
		start := now.Add(-time.Duration(days) * 24 * time.Hour)
		g := sim.New(sim.Options{Start: start, Seed: 1, Rate: rate, SeqBase: 1, LateBatches: true, AppOps: true, Scenarios: all,
			ScenarioStart: now.Add(-40 * time.Hour), ScenarioEnd: now})
		g.PlanScenario(start, now)
		total := 0
		began := time.Now()
		put := func(evs []sim.Event) {
			for len(evs) > 0 {
				n := min(len(evs), 500)
				batch := make([]*model.Event, 0, n)
				for _, se := range evs[:n] {
					raw, _ := json.Marshal(se)
					ev, err := model.ParseEvent(raw, now)
					if err != nil {
						t.Fatal(err)
					}
					batch = append(batch, ev)
				}
				if _, err := st.Ingest(ctx, dev, "sim", batch, now); err != nil {
					t.Fatal(err)
				}
				total += n
				evs = evs[n:]
			}
		}
		for at := start; at.Before(now); {
			next := at.Add(6 * time.Hour)
			if next.After(now) {
				next = now
			}
			put(g.Advance(next))
			at = next
		}
		put(g.Drain())
		t.Logf("database: %d events in %s (%.0f/s)", total, time.Since(began).Round(time.Second), float64(total)/time.Since(began).Seconds())
	}
	events, err := st.MaxEventPK(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var dirty int64
	if dirty, err = st.DirtyCount(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("database: %d events, %d hours to evaluate", events, dirty)

	e := NewEngine(st, Defaults(), Options{ThreatLists: false, Budget: time.Hour, Retention: 90 * 24 * time.Hour})
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // heap sampling
		defer wg.Done()
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > peak.Load() {
				peak.Store(ms.HeapInuse)
			}
		}
	}()
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	// 1. The whole backlog (every hour of the period), with ingestion running in parallel.
	lat := make(chan time.Duration, 100000)
	ingestStop := make(chan struct{})
	var iwg sync.WaitGroup
	iwg.Add(1)
	go func() {
		defer iwg.Done()
		g := sim.New(sim.Options{Start: now.Add(-6 * time.Hour), Seed: 99, Rate: 4, SeqBase: 1 << 40, AppOps: true})
		at := now.Add(-6 * time.Hour)
		for {
			select {
			case <-ingestStop:
				return
			default:
			}
			at = at.Add(2 * time.Minute)
			evs := g.Advance(at)
			for len(evs) > 0 {
				n := min(len(evs), 500)
				batch := make([]*model.Event, 0, n)
				for _, se := range evs[:n] {
					raw, _ := json.Marshal(se)
					if ev, err := model.ParseEvent(raw, time.Now()); err == nil {
						batch = append(batch, ev)
					}
				}
				t0 := time.Now()
				if _, err := st.Ingest(ctx, dev, "sim", batch, time.Now()); err != nil {
					t.Error(err)
					return
				}
				lat <- time.Since(t0)
				evs = evs[n:]
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	time.Sleep(2 * time.Second) // baseline latencies
	baseline := drain(lat)
	t0 := time.Now()
	stats, err := e.RunOnce(ctx)
	full := time.Since(t0)
	during := drain(lat)
	close(ingestStop)
	iwg.Wait()
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("full backlog: %d hours in %s (%d rounds, %d detections), max heap %d MiB (idle %d MiB)",
		stats.Hours, full.Round(time.Millisecond), stats.Rounds, stats.Findings, peak.Load()>>20, base.HeapInuse>>20)
	t.Logf("ingestion (batches of 500) without the work: %s; during: %s", pct(baseline), pct(during))

	// 2. Steady state: one late batch (two hours of net.connect and net.dns) re-marks two hours.
	g := sim.New(sim.Options{Start: now.Add(-30 * time.Hour), Seed: 5, Rate: rate, SeqBase: 1 << 41, AppOps: true})
	g.Advance(now.Add(-28 * time.Hour))
	var batch []*model.Event
	for _, se := range g.Drain() {
		raw, _ := json.Marshal(se)
		if ev, err := model.ParseEvent(raw, now); err == nil {
			batch = append(batch, ev)
		}
	}
	for _, se := range g.Advance(now.Add(-26 * time.Hour)) {
		raw, _ := json.Marshal(se)
		if ev, err := model.ParseEvent(raw, now); err == nil && len(batch) < 500 {
			batch = append(batch, ev)
		}
	}
	if _, err := st.Ingest(ctx, dev, "sim", batch, now); err != nil {
		t.Fatal(err)
	}
	t0 = time.Now()
	stats, err = e.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("regular run after a late batch: %d hours in %s", stats.Hours, time.Since(t0).Round(time.Millisecond))
}

func drain(c chan time.Duration) []time.Duration {
	var out []time.Duration
	for {
		select {
		case d := <-c:
			out = append(out, d)
		default:
			return out
		}
	}
}

func pct(v []time.Duration) string {
	if len(v) == 0 {
		return "no batch"
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return strconv.Itoa(len(v)) + " batches, median " + v[len(v)/2].Round(time.Millisecond).String() +
		", p99 " + v[len(v)*99/100].Round(time.Millisecond).String() + ", max " + v[len(v)-1].Round(time.Millisecond).String()
}
