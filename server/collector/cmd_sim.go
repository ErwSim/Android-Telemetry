package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

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
	if err := fl.Parse(args); err != nil {
		return err
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
	g := sim.New(sim.Options{Start: start, Seed: s, Rate: *rate, AgentVersion: *version, SeqBase: now.UnixMilli()})

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
		stats.print()
		if !*follow {
			return nil
		}
	} else {
		// Without history, show every type during the first hour.
		g.PlanScenario(now, now.Add(time.Hour))
	}

	fmt.Fprintf(os.Stderr, "Mode continu (envoi toutes les %s, Ctrl-C pour arrêter)…\n", *interval)
	t := time.NewTicker(*interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr)
			stats.print()
			return nil
		case <-t.C:
		}
		if err := sendAll(ctx, client, g.Advance(time.Now().UTC()), *batch, stats); err != nil {
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
