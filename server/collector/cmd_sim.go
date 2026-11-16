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

	"github.com/erwsim/android-telemetry/server/collector/internal/adguard"
	"github.com/erwsim/android-telemetry/server/collector/internal/enroll"
	"github.com/erwsim/android-telemetry/server/collector/internal/sim"
)

func cmdSim(args []string) error {
	fl := flag.NewFlagSet("sim", flag.ContinueOnError)
	enrollPath := fl.String("enroll", "", "fichier .vigie de l'appareil simulé (requis)")
	url := fl.String("url", "", "URL d'ingestion (défaut : celle du fichier .vigie)")
	backfill := fl.Duration("backfill", 0, "génère d'abord l'historique de cette durée (ex. 24h, 168h)")
	follow := fl.Bool("follow", false, "avec --backfill : continuer ensuite en temps réel")
	rate := fl.Float64("rate", 1, "facteur de volume (trafic DNS/connexions, notifications) ; 1 = réaliste")
	interval := fl.Duration("interval", 15*time.Second, "mode continu : intervalle entre deux envois")
	seed := fl.Int64("seed", 0, "graine aléatoire (0 = dérivée de l'heure)")
	batch := fl.Int("batch", 500, "taille maximale des lots (1 à 500)")
	version := fl.String("agent-version", "1.0.0-sim", "agent_version annoncée")
	cmdMode := fl.String("commands", "stream", "canal de commandes en mode continu : stream (flux permanent), poll (interrogation) ou off")
	pollEvery := fl.Duration("poll-interval", time.Minute, "avec --commands poll : intervalle d'interrogation (1 à 15 min)")
	cmdCode := fl.String("command-code", "", "code de commande de l'appareil simulé (12 caractères au moins) ; vide : commandes sensibles refusées (no_code_configured)")
	allowWipe := fl.Bool("allow-wipe", false, "réglage « Autoriser l'effacement à distance » (éteint par défaut : wipe refusé avec disabled)")
	clockSkew := fl.Duration("clock-skew", 0, "décalage de l'horloge du téléphone simulé (ex. 2h : commandes refusées avec expired)")
	notifContent := fl.Bool("notification-content", true, "option « Contenu des notifications » de l'APK compagnon (titre et texte, codes masqués)")
	fakeAG := fl.String("fake-adguard", "", "adresse d'écoute d'un faux AdGuard Home alimenté par les net.dns simulés (ex. 127.0.0.1:3001)")
	fakeAGUser := fl.String("fake-adguard-user", "", "faux AdGuard Home : utilisateur (authentification de base ; vide : aucune)")
	fakeAGPass := fl.String("fake-adguard-password", "", "faux AdGuard Home : mot de passe")
	fakeAGClient := fl.String("fake-adguard-client", "", "faux AdGuard Home : ClientID des requêtes (défaut : nom de l'appareil)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	switch *cmdMode {
	case "stream", "poll", "off":
	default:
		return errors.New("--commands : stream, poll ou off")
	}
	if *pollEvery < time.Minute || *pollEvery > 15*time.Minute {
		return errors.New("--poll-interval doit être entre 1m et 15m")
	}
	if *enrollPath == "" {
		return errors.New("--enroll <fichier.vigie> est requis")
	}
	if *batch < 1 || *batch > 500 {
		return errors.New("--batch doit être entre 1 et 500")
	}
	if *rate <= 0 || *rate > 100 {
		return errors.New("--rate doit être dans ]0, 100]")
	}
	if *backfill < 0 || *backfill > 90*24*time.Hour {
		return errors.New("--backfill doit être entre 0 et 2160h")
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
		return fmt.Errorf("authentification refusée ou serveur injoignable : %w", err)
	}
	fmt.Fprintf(os.Stderr, "Appareil %s (%s) authentifié.\n", f.DeviceID, f.DeviceName)

	now := time.Now().UTC()
	s := *seed
	if s == 0 {
		s = now.UnixNano()
	}
	stats := &simStats{types: map[string]int{}}
	start := now.Add(-*backfill)
	opts := sim.Options{Start: start, Seed: s, Rate: *rate, AgentVersion: *version, SeqBase: now.UnixMilli(),
		PrivateDNSHost: f.PrivateDNSHost, LateBatches: true, NotificationContent: *notifContent}
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
		fmt.Fprintf(os.Stderr, "Faux AdGuard Home : http://%s (%d requêtes dans le journal) — VIGIE_ADGUARD_URL=http://%s\n",
			ln.Addr(), fake.Len(), ln.Addr())
		return nil
	}

	if *backfill > 0 {
		g.PlanScenario(start, now)
		fmt.Fprintf(os.Stderr, "Historique : %s → %s\n", start.Format(time.RFC3339), now.Format(time.RFC3339))
		for t := start; t.Before(now); {
			next := t.Add(time.Hour)
			if next.After(now) {
				next = now
			}
			if err := sendAll(ctx, client, g.Advance(next), *batch, stats); err != nil {
				return err
			}
			t = next
			fmt.Fprintf(os.Stderr, "\r  %s : %d événements envoyés", t.Format("2006-01-02 15:04"), stats.sent)
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
		fmt.Fprintf(os.Stderr, "Canal de commandes : %s (code de commande %s, effacement à distance %s)\n", *cmdMode,
			map[bool]string{true: "défini", false: "non défini"}[*cmdCode != ""], map[bool]string{true: "autorisé", false: "refusé"}[*allowWipe])
	}
	fmt.Fprintf(os.Stderr, "Mode continu (envoi toutes les %s, Ctrl-C pour arrêter)…\n", *interval)
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
		fmt.Fprintf(os.Stderr, "\r  %s : %d événements envoyés", time.Now().Format("15:04:05"), stats.sent)
	}
}

type simStats struct {
	sent, accepted, dups, rejected int
	types                          map[string]int
}

func (s *simStats) print() {
	fmt.Fprintf(os.Stderr, "Envoyés : %d, acceptés : %d, doublons : %d, rejetés : %d, types : %d\n",
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
			fmt.Fprintf(os.Stderr, "\nrejet : %s %s", r.ID, r.Reason)
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
		s = "telephone"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
