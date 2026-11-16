package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/adguard"
	"github.com/erwsim/watchpost/server/collector/internal/enroll"
	"github.com/erwsim/watchpost/server/collector/internal/sim"
)

func cmdSim(args []string) error {
	fl := flag.NewFlagSet("sim", flag.ContinueOnError)
	enrollPath := fl.String("enroll", "", ".watchpost file of the simulated device (required)")
	url := fl.String("url", "", "ingestion URL (default: the one in the .watchpost file)")
	backfill := fl.Duration("backfill", 0, "first generate the history of this duration (e.g. 24h, 168h)")
	follow := fl.Bool("follow", false, "with --backfill: then keep going in real time")
	rate := fl.Float64("rate", 1, "volume factor (DNS/connection traffic, notifications); 1 = realistic")
	interval := fl.Duration("interval", 15*time.Second, "continuous mode: interval between two uploads")
	seed := fl.Int64("seed", 0, "random seed (0 = derived from the clock)")
	batch := fl.Int("batch", 500, "maximum batch size (1 to 500)")
	version := fl.String("agent-version", "1.0.0-sim", "announced agent_version")
	cmdMode := fl.String("commands", "stream", "command channel in continuous mode: stream (permanent stream), poll (polling) or off")
	pollEvery := fl.Duration("poll-interval", time.Minute, "with --commands poll: polling interval (1 to 15 min)")
	cmdCode := fl.String("command-code", "", "command passphrase of the simulated device (at least 12 characters); empty: sensitive commands refused (no_code_configured)")
	allowWipe := fl.Bool("allow-wipe", false, "\"Allow remote erase\" setting (off by default: wipe refused with disabled)")
	clockSkew := fl.Duration("clock-skew", 0, "clock offset of the simulated phone (e.g. 2h: commands refused with expired)")
	notifContent := fl.Bool("notification-content", true, "\"Notification content\" option of the companion APK (title and text, codes masked)")
	fakeAG := fl.String("fake-adguard", "", "listen address of a fake AdGuard Home fed by the simulated net.dns events (e.g. 127.0.0.1:3001)")
	fakeAGUser := fl.String("fake-adguard-user", "", "fake AdGuard Home: user (basic authentication; empty: none)")
	fakeAGPass := fl.String("fake-adguard-password", "", "fake AdGuard Home: password")
	fakeAGClient := fl.String("fake-adguard-client", "", "fake AdGuard Home: ClientID of the queries (default: device name)")
	scenario := fl.String("scenario", sim.ScenarioHealthy, "comma-separated scenarios (see below); healthy: none")
	appOps := fl.Bool("app-ops", true, "emit app.ops (experimental on the agent side: =false to simulate its absence)")
	fl.Usage = func() {
		fmt.Fprintln(fl.Output(), "Usage: watchpost-collector sim --enroll <file.watchpost> [options]")
		fl.PrintDefaults()
		fmt.Fprintln(fl.Output(), "\nScenarios (--scenario):")
		for _, i := range sim.ScenarioInfo {
			fmt.Fprintf(fl.Output(), "  %-18s %s\n", i.Name, i.Desc)
		}
	}
	if err := fl.Parse(args); err != nil {
		return err
	}
	switch *cmdMode {
	case "stream", "poll", "off":
	default:
		return errors.New("--commands: stream, poll or off")
	}
	if *pollEvery < time.Minute || *pollEvery > 15*time.Minute {
		return errors.New("--poll-interval must be between 1m and 15m")
	}
	if *enrollPath == "" {
		return errors.New("--enroll <file.watchpost> is required")
	}
	if *batch < 1 || *batch > 500 {
		return errors.New("--batch must be between 1 and 500")
	}
	if *rate <= 0 || *rate > 100 {
		return errors.New("--rate must be in ]0, 100]")
	}
	if *backfill < 0 || *backfill > 90*24*time.Hour {
		return errors.New("--backfill must be between 0 and 2160h")
	}
	scenarios, err := sim.ParseScenarios(*scenario)
	if err != nil {
		return fmt.Errorf("--scenario: %w", err)
	}
	f, err := enroll.Read(*enrollPath)
	if err != nil {
		return err
	}
	client, err := sim.NewClient(f, *url, *version)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := client.Ping(ctx); err != nil {
		return fmt.Errorf("authentication refused or server unreachable: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Device %s (%s) authenticated.\n", f.DeviceID, f.DeviceName)

	now := time.Now().UTC()
	s := *seed
	if s == 0 {
		s = now.UnixNano()
	}
	stats := &simStats{types: map[string]int{}}
	start := now.Add(-*backfill)
	opts := sim.Options{Start: start, Seed: s, Rate: *rate, AgentVersion: *version, SeqBase: now.UnixMilli(),
		PrivateDNSHost: f.PrivateDNSHost, LateBatches: true, NotificationContent: *notifContent, AppOps: *appOps, Scenarios: scenarios}
	if len(scenarios) > 0 {
		// The attacks start late enough for the phone to have a history (at most the last 48 h of the
		// backfill, 40 % of it when shorter); without backfill, in a minute.
		opts.ScenarioStart = now.Add(time.Minute)
		if *backfill > 0 {
			opts.ScenarioStart = now.Add(-min(48*time.Hour, *backfill*4/10))
		}
		if *backfill > 0 {
			opts.ScenarioEnd = now // events placed within the history (exfiltration spike)
		}
		fmt.Fprintf(os.Stderr, "Scenarios: %s, starting at %s\n", strings.Join(scenarios, ", "), opts.ScenarioStart.Format(time.RFC3339))
	}
	var fake *adguard.Fake
	if *fakeAG != "" {
		fake = adguard.NewFake(*fakeAGUser, *fakeAGPass)
		client := *fakeAGClient
		if client == "" {
			client = clientIDFrom(f.DeviceName)
		}
		opts.OnDNS = func(ts time.Time, host string) { fake.AddQuery(ts, "203.0.113.25", client, host) }
	}
	g := sim.New(opts)
	// The fake AdGuard Home starts listening once the history is in its query log: AdGuard Home never
	// inserts old entries, and the collector does not read again what is older than its position.
	startFake := func() error {
		if fake == nil {
			return nil
		}
		ln, err := net.Listen("tcp", *fakeAG)
		if err != nil {
			return fmt.Errorf("--fake-adguard : %w", err)
		}
		srv := &http.Server{Handler: fake, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		go func() { <-ctx.Done(); _ = srv.Close() }()
		fmt.Fprintf(os.Stderr, "Fake AdGuard Home: http://%s (%d queries in the log) - WATCHPOST_ADGUARD_URL=http://%s\n",
			ln.Addr(), fake.Len(), ln.Addr())
		return nil
	}

	if *backfill > 0 {
		g.PlanScenario(start, now)
		fmt.Fprintf(os.Stderr, "History: %s -> %s\n", start.Format(time.RFC3339), now.Format(time.RFC3339))
		for t := start; t.Before(now); {
			next := t.Add(time.Hour)
			if next.After(now) {
				next = now
			}
			if err := sendAll(ctx, client, g.Advance(next), *batch, stats); err != nil {
				return err
			}
			t = next
			fmt.Fprintf(os.Stderr, "\r  %s: %d events sent", t.Format("2006-01-02 15:04"), stats.sent)
		}
		fmt.Fprintln(os.Stderr)
		if !*follow {
			// Finite run: the last late batch the real agent would send later goes out now.
			if err := sendAll(ctx, client, g.Drain(), *batch, stats); err != nil {
				return err
			}
		}
		stats.print()
		if !*follow {
			return nil
		}
	} else {
		// Without history, show every type during the first hour.
		g.PlanScenario(now, now.Add(time.Hour))
	}

	if err := startFake(); err != nil {
		return err
	}
	inj := make(chan sim.Injection, 64)
	if *cmdMode != "off" {
		agent, err := sim.NewCommandAgent(client, sim.AgentOptions{DeviceID: f.DeviceID, Code: *cmdCode, AllowWipe: *allowWipe,
			ClockSkew: *clockSkew, Log: os.Stderr}, inj)
		if err != nil {
			return err
		}
		if *cmdMode == "stream" {
			go agent.RunStream(ctx)
		} else {
			go agent.RunPoll(ctx, *pollEvery)
		}
		fmt.Fprintf(os.Stderr, "Command channel: %s (command passphrase %s, remote erase %s)\n", *cmdMode,
			map[bool]string{true: "set", false: "not set"}[*cmdCode != ""], map[bool]string{true: "allowed", false: "refused"}[*allowWipe])
	}
	fmt.Fprintf(os.Stderr, "Continuous mode (upload every %s, Ctrl-C to stop)...\n", *interval)
	t := time.NewTicker(*interval)
	defer t.Stop()
	for {
		to := time.Now().UTC()
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr)
			stats.print()
			return nil
		case <-t.C:
			to = time.Now().UTC()
		case in := <-inj:
			// Results and positions of commands are sent at once, like the agent does.
			for {
				if in.Locate {
					g.Locate(in.At)
				} else {
					g.Inject(in.At, in.Type, in.Sev, in.Data)
				}
				if a := in.At.UTC().Add(time.Millisecond); a.After(to) {
					to = a
				}
				select {
				case in = <-inj:
					continue
				default:
				}
				break
			}
			if n := time.Now().UTC(); n.After(to) {
				to = n
			}
		}
		if err := sendAll(ctx, client, g.Advance(to), *batch, stats); err != nil {
			if errors.Is(err, context.Canceled) {
				continue
			}
			return err
		}
		fmt.Fprintf(os.Stderr, "\r  %s: %d events sent", time.Now().Format("15:04:05"), stats.sent)
	}
}

type simStats struct {
	sent, accepted, dups, rejected int
	types                          map[string]int
}

func (s *simStats) print() {
	fmt.Fprintf(os.Stderr, "Sent: %d, accepted: %d, duplicates: %d, rejected: %d, types: %d\n",
		s.sent, s.accepted, s.dups, s.rejected, len(s.types))
	keys := make([]string, 0, len(s.types))
	for k := range s.types {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(os.Stderr, "  %-26s %7d\n", k, s.types[k])
	}
}

func sendAll(ctx context.Context, c *sim.Client, evs []sim.Event, batch int, st *simStats) error {
	for len(evs) > 0 {
		n := min(batch, len(evs))
		res, err := c.Send(ctx, evs[:n])
		if err != nil {
			return err
		}
		for _, e := range evs[:n] {
			st.types[e.Type]++
		}
		st.sent += n
		st.accepted += res.Accepted
		st.dups += res.Duplicates
		st.rejected += len(res.Rejected)
		for _, r := range res.Rejected {
			fmt.Fprintf(os.Stderr, "\nrejected: %s %s", r.ID, r.Reason)
		}
		evs = evs[n:]
	}
	return nil
}

// clientIDFrom derives an AdGuard ClientID ([a-z0-9-], 64 at most) from the device name.
func clientIDFrom(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if s == "" {
		s = "phone"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
