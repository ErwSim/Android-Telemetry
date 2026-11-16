package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/erwsim/watchpost/server/collector/internal/auth"
	"github.com/erwsim/watchpost/server/collector/internal/config"
	"github.com/erwsim/watchpost/server/collector/internal/enroll"
	"github.com/erwsim/watchpost/server/collector/internal/model"
	"github.com/erwsim/watchpost/server/collector/internal/pki"
	"github.com/erwsim/watchpost/server/collector/internal/store"
)

func openStore(ctx context.Context) (*config.Config, *store.Store, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(ctx, cfg.DBPath())
	if err != nil {
		return nil, nil, fmt.Errorf("database %s: %w", cfg.DBPath(), err)
	}
	return cfg, st, nil
}

// fileParams resolves what enroll and renew write into the .watchpost file (URL, DNS host, server CA).
func fileParams(cfg *config.Config, ingestURL string) (enroll.Params, error) {
	u := ingestURL
	if u == "" {
		u = cfg.PublicIngestURL
	}
	if u == "" {
		return enroll.Params{}, errors.New("unknown ingestion URL: set WATCHPOST_PUBLIC_INGEST_URL or --ingest-url")
	}
	pu, err := enroll.CheckIngestURL(u)
	if err != nil {
		return enroll.Params{}, err
	}
	if pu.Scheme != "https" {
		fmt.Fprintln(os.Stderr, "warning: ingestion URL uses http, reserve it for local development")
	}
	p := enroll.Params{IngestURL: u, PrivateDNSHost: cfg.PrivateDNSHost}
	if cfg.ServerCAFile != "" {
		b, err := os.ReadFile(cfg.ServerCAFile)
		if err != nil {
			return enroll.Params{}, fmt.Errorf("WATCHPOST_SERVER_CA_FILE: %w", err)
		}
		if _, err := pki.FingerprintPEM(b); err != nil {
			return enroll.Params{}, fmt.Errorf("WATCHPOST_SERVER_CA_FILE: %w", err)
		}
		p.ServerCAPEM = string(b)
	}
	return p, nil
}

func cmdEnroll(args []string) error {
	fl := flag.NewFlagSet("enroll", flag.ContinueOnError)
	name := fl.String("name", "", "device name (e.g. phone)")
	out := fl.String("out", "", ".watchpost file to write")
	ingestURL := fl.String("ingest-url", "", "ingestion URL (default: WATCHPOST_PUBLIC_INGEST_URL)")
	force := fl.Bool("force", false, "overwrite the output file if it exists")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *name == "" || *out == "" {
		return errors.New("--name and --out are required")
	}
	ctx := context.Background()
	cfg, st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	params, err := fileParams(cfg, *ingestURL)
	if err != nil {
		return err
	}
	params.Name = *name
	ca, _, err := pki.LoadOrCreate(cfg.PKIDir(), time.Now())
	if err != nil {
		return fmt.Errorf("PKI: %w", err)
	}
	// Refuse early if the output exists, before creating the device.
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite it)", *out)
		}
	}
	f, err := enroll.Create(ctx, st, ca, params, time.Now())
	if err != nil {
		return err
	}
	if err := f.Write(*out, *force); err != nil {
		return fmt.Errorf("writing %s: %w (device %s created: revoke it)", *out, err, f.DeviceID)
	}
	fp, _ := pki.FingerprintPEM([]byte(f.ClientCertPEM))
	fmt.Printf("Device enrolled: %s (%s)\n", f.DeviceID, f.DeviceName)
	fmt.Printf("Client certificate fingerprint (SHA-256): %s\n", fp)
	fmt.Printf("Enrollment file: %s\n", *out)
	fmt.Println("This file contains secrets: transfer it over a cable (adb push) or an encrypted channel, then delete it.")
	return nil
}

func cmdRenew(args []string) error {
	// The device_id is positional, before or after the flags.
	var id string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	fl := flag.NewFlagSet("renew", flag.ContinueOnError)
	out := fl.String("out", "", ".watchpost file to write")
	ingestURL := fl.String("ingest-url", "", "ingestion URL (default: WATCHPOST_PUBLIC_INGEST_URL)")
	force := fl.Bool("force", false, "overwrite the output file if it exists")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if id == "" && fl.NArg() == 1 {
		id = fl.Arg(0)
	} else if fl.NArg() != 0 {
		return errors.New("usage: watchpost-collector renew <device_id> --out <file.watchpost> [--ingest-url URL] [--force]")
	}
	if id == "" || *out == "" {
		return errors.New("usage: watchpost-collector renew <device_id> --out <file.watchpost> [--ingest-url URL] [--force]")
	}
	ctx := context.Background()
	cfg, st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	params, err := fileParams(cfg, *ingestURL)
	if err != nil {
		return err
	}
	ca, _, err := pki.LoadOrCreate(cfg.PKIDir(), time.Now())
	if err != nil {
		return fmt.Errorf("PKI: %w", err)
	}
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite it)", *out)
		}
	}
	f, err := enroll.Renew(ctx, st, ca, id, params, time.Now())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			return fmt.Errorf("unknown device: %s", id)
		case errors.Is(err, store.ErrRevoked):
			return fmt.Errorf("device %s is revoked: renewal is impossible (use \"enroll\" for a new device)", id)
		}
		return err
	}
	if err := f.Write(*out, *force); err != nil {
		return fmt.Errorf("writing %s: %w (the pending renewal is unusable, the device keeps its current token and certificate; run \"renew\" again)", *out, err)
	}
	fp, _ := pki.FingerprintPEM([]byte(f.ClientCertPEM))
	exp, _ := pki.NotAfterPEM([]byte(f.ClientCertPEM))
	fmt.Printf("Renewal of %s (%s): new token and new certificate issued, same identifier.\n", f.DeviceID, f.DeviceName)
	fmt.Printf("New certificate fingerprint (SHA-256): %s\n", fp)
	fmt.Printf("New certificate valid until %s\n", exp.Local().Format("2006-01-02"))
	fmt.Printf("Enrollment file: %s\n", *out)
	fmt.Println("The old token and the old certificate stay accepted until the first upload with the new file, then are refused.")
	fmt.Println("This file contains secrets: transfer it over a cable (adb push) or an encrypted channel, then delete it.")
	return nil
}

func cmdDevices(args []string) error {
	fl := flag.NewFlagSet("devices", flag.ContinueOnError)
	asJSON := fl.Bool("json", false, "JSON output")
	if err := fl.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	_, st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	devs, err := st.ListDevices(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		type row struct {
			DeviceID     string  `json:"device_id"`
			Name         string  `json:"name"`
			EnrolledAt   string  `json:"enrolled_at"`
			LastSeen     *string `json:"last_seen"`
			RevokedAt    *string `json:"revoked_at"`
			AgentVersion string  `json:"agent_version"`
			CertSHA256   string  `json:"cert_sha256"`
			// CertNotAfter is the expiry of the current certificate (null if unreadable).
			CertNotAfter *string `json:"cert_not_after"`
			// RenewalPending: a renewed pair waits for its first use; PendingCertNotAfter is its expiry.
			RenewalPending      bool    `json:"renewal_pending"`
			PendingSince        *string `json:"renewal_issued_at"`
			PendingCertNotAfter *string `json:"pending_cert_not_after"`
		}
		rows := []row{}
		for _, d := range devs {
			r := row{DeviceID: d.DeviceID, Name: d.Name, EnrolledAt: model.FormatTS(d.EnrolledAt), AgentVersion: d.AgentVersion, CertSHA256: d.CertSHA256}
			if d.LastSeen != nil {
				s := model.FormatTS(*d.LastSeen)
				r.LastSeen = &s
			}
			if d.RevokedAt != nil {
				s := model.FormatTS(*d.RevokedAt)
				r.RevokedAt = &s
			}
			if t, err := pki.NotAfterPEM([]byte(d.CertPEM)); err == nil {
				s := model.FormatTS(t)
				r.CertNotAfter = &s
			}
			if d.HasPending() {
				r.RenewalPending = true
				if d.NextIssuedAt != nil {
					s := model.FormatTS(*d.NextIssuedAt)
					r.PendingSince = &s
				}
				if t, err := pki.NotAfterPEM([]byte(d.NextCertPEM)); err == nil {
					s := model.FormatTS(t)
					r.PendingCertNotAfter = &s
				}
			}
			rows = append(rows, r)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"devices": rows})
	}
	if len(devs) == 0 {
		fmt.Println("No enrolled devices.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DEVICE ID\tNAME\tENROLLED\tLAST SEEN\tVERSION\tSTATE\tCERTIFICATE\tEXPIRES")
	for _, d := range devs {
		seen := "never"
		if d.LastSeen != nil {
			seen = d.LastSeen.Local().Format("2006-01-02 15:04")
		}
		state := "active"
		if d.RevokedAt != nil {
			state = "revoked " + d.RevokedAt.Local().Format("2006-01-02 15:04")
		}
		ver := d.AgentVersion
		if ver == "" {
			ver = "-"
		}
		if d.HasPending() {
			state += ", renewal pending"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s…\t%s\n", d.DeviceID, d.Name, d.EnrolledAt.Local().Format("2006-01-02 15:04"),
			seen, ver, state, d.CertSHA256[:16], expiryLabel(d.CertPEM, time.Now()))
	}
	return tw.Flush()
}

func cmdRevoke(args []string) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: watchpost-collector revoke <device_id>")
	}
	ctx := context.Background()
	_, st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.RevokeDevice(ctx, args[0], time.Now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("unknown device: %s", args[0])
		}
		return err
	}
	fmt.Printf("Device %s revoked: its token and certificate are refused from now on (including any pending renewal).\n", args[0])
	fmt.Println("Its data stays available in the console. To enroll it again, use \"enroll\".")
	return nil
}

func cmdUser(args []string) error {
	if len(args) != 2 || args[0] != "set-password" {
		return errors.New("usage: watchpost-collector user set-password <name>")
	}
	username := args[1]
	if !auth.ValidUsername(username) {
		return errors.New("invalid name (1 to 64 characters among letters, digits, \"_ - . @\")")
	}
	password, err := readPassword(os.Stdin)
	if err != nil {
		return err
	}
	if err := auth.ValidPassword(password); err != nil {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	ctx := context.Background()
	_, st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	created, err := st.UpsertUser(ctx, username, hash, time.Now())
	if err != nil {
		return err
	}
	if created {
		fmt.Printf("Console account \"%s\" created.\n", username)
	} else {
		fmt.Printf("Password of \"%s\" changed; its open sessions are closed.\n", username)
	}
	return nil
}

// readPassword reads a password: twice without echo on a terminal, else one line of stdin.
func readPassword(in *os.File) (string, error) {
	fd := int(in.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Password: ")
		p1, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(os.Stderr, "Confirmation: ")
		p2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(p1) != string(p2) {
			return "", errors.New("the two entries differ")
		}
		return string(p1), nil
	}
	line, err := bufio.NewReader(io.LimitReader(in, auth.MaxPasswordLen+2)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// expiryLabel formats a certificate expiry for the devices table: date, then days left or "EXPIRED".
func expiryLabel(certPEM string, now time.Time) string {
	t, err := pki.NotAfterPEM([]byte(certPEM))
	if err != nil {
		return "unknown"
	}
	days := int(t.Sub(now).Hours() / 24)
	switch {
	case !t.After(now):
		return t.Local().Format("2006-01-02") + " (EXPIRED)"
	case days < 30:
		return fmt.Sprintf("%s (in %d d, to renew)", t.Local().Format("2006-01-02"), days)
	}
	return fmt.Sprintf("%s (in %d d)", t.Local().Format("2006-01-02"), days)
}
