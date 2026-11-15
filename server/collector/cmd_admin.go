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

	"github.com/erwsim/android-telemetry/server/collector/internal/auth"
	"github.com/erwsim/android-telemetry/server/collector/internal/config"
	"github.com/erwsim/android-telemetry/server/collector/internal/enroll"
	"github.com/erwsim/android-telemetry/server/collector/internal/model"
	"github.com/erwsim/android-telemetry/server/collector/internal/pki"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

func openStore(ctx context.Context) (*config.Config, *store.Store, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(ctx, cfg.DBPath())
	if err != nil {
		return nil, nil, fmt.Errorf("base de données %s : %w", cfg.DBPath(), err)
	}
	return cfg, st, nil
}

func cmdEnroll(args []string) error {
	fl := flag.NewFlagSet("enroll", flag.ContinueOnError)
	name := fl.String("name", "", "nom de l'appareil (ex. s25)")
	out := fl.String("out", "", "fichier .vigie à écrire")
	ingestURL := fl.String("ingest-url", "", "URL d'ingestion (défaut : VIGIE_PUBLIC_INGEST_URL)")
	force := fl.Bool("force", false, "écraser le fichier de sortie s'il existe")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *name == "" || *out == "" {
		return errors.New("--name et --out sont requis")
	}
	ctx := context.Background()
	cfg, st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	u := *ingestURL
	if u == "" {
		u = cfg.PublicIngestURL
	}
	if u == "" {
		return errors.New("URL d'ingestion inconnue : définissez VIGIE_PUBLIC_INGEST_URL ou --ingest-url")
	}
	pu, err := enroll.CheckIngestURL(u)
	if err != nil {
		return err
	}
	if pu.Scheme != "https" {
		fmt.Fprintln(os.Stderr, "attention : URL d'ingestion en http, à réserver au développement local")
	}
	var serverCA string
	if cfg.ServerCAFile != "" {
		b, err := os.ReadFile(cfg.ServerCAFile)
		if err != nil {
			return fmt.Errorf("VIGIE_SERVER_CA_FILE : %w", err)
		}
		if _, err := pki.FingerprintPEM(b); err != nil {
			return fmt.Errorf("VIGIE_SERVER_CA_FILE : %w", err)
		}
		serverCA = string(b)
	}
	ca, _, err := pki.LoadOrCreate(cfg.PKIDir(), time.Now())
	if err != nil {
		return fmt.Errorf("PKI : %w", err)
	}
	// Refuse early if the output exists, before creating the device.
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("%s existe déjà (utilisez --force pour l'écraser)", *out)
		}
	}
	f, err := enroll.Create(ctx, st, ca, enroll.Params{
		Name: *name, IngestURL: u, PrivateDNSHost: cfg.PrivateDNSHost, ServerCAPEM: serverCA,
	}, time.Now())
	if err != nil {
		return err
	}
	if err := f.Write(*out, *force); err != nil {
		return fmt.Errorf("écriture de %s : %w (appareil %s créé : révoquez-le)", *out, err, f.DeviceID)
	}
	fp, _ := pki.FingerprintPEM([]byte(f.ClientCertPEM))
	fmt.Printf("Appareil enrôlé : %s (%s)\n", f.DeviceID, f.DeviceName)
	fmt.Printf("Empreinte du certificat client (SHA-256) : %s\n", fp)
	fmt.Printf("Fichier d'enrôlement : %s\n", *out)
	fmt.Println("Ce fichier contient des secrets : transférez-le par câble (adb push) ou canal chiffré, puis supprimez-le.")
	return nil
}

func cmdDevices(args []string) error {
	fl := flag.NewFlagSet("devices", flag.ContinueOnError)
	asJSON := fl.Bool("json", false, "sortie JSON")
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
			rows = append(rows, r)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"devices": rows})
	}
	if len(devs) == 0 {
		fmt.Println("Aucun appareil enrôlé.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "IDENTIFIANT\tNOM\tENRÔLÉ LE\tDERNIER CONTACT\tVERSION\tÉTAT\tCERTIFICAT")
	for _, d := range devs {
		seen := "jamais"
		if d.LastSeen != nil {
			seen = d.LastSeen.Local().Format("2006-01-02 15:04")
		}
		state := "actif"
		if d.RevokedAt != nil {
			state = "révoqué le " + d.RevokedAt.Local().Format("2006-01-02 15:04")
		}
		ver := d.AgentVersion
		if ver == "" {
			ver = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s…\n", d.DeviceID, d.Name, d.EnrolledAt.Local().Format("2006-01-02 15:04"),
			seen, ver, state, d.CertSHA256[:16])
	}
	return tw.Flush()
}

func cmdRevoke(args []string) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("utilisation : vigie-collector revoke <device_id>")
	}
	ctx := context.Background()
	_, st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.RevokeDevice(ctx, args[0], time.Now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("appareil inconnu : %s", args[0])
		}
		return err
	}
	fmt.Printf("Appareil %s révoqué : son jeton et son certificat sont refusés dès maintenant.\n", args[0])
	fmt.Println("Ses données restent consultables dans la console. Pour le réenrôler, utilisez « enroll ».")
	return nil
}

func cmdUser(args []string) error {
	if len(args) != 2 || args[0] != "set-password" {
		return errors.New("utilisation : vigie-collector user set-password <nom>")
	}
	username := args[1]
	if !auth.ValidUsername(username) {
		return errors.New("nom invalide (1 à 64 caractères parmi lettres, chiffres, « _ - . @ »)")
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
		fmt.Printf("Compte console « %s » créé.\n", username)
	} else {
		fmt.Printf("Mot de passe de « %s » modifié ; ses sessions ouvertes sont fermées.\n", username)
	}
	return nil
}

// readPassword reads a password: twice without echo on a terminal, else one line of stdin.
func readPassword(in *os.File) (string, error) {
	fd := int(in.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Mot de passe : ")
		p1, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(os.Stderr, "Confirmation : ")
		p2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(p1) != string(p2) {
			return "", errors.New("les deux saisies diffèrent")
		}
		return string(p1), nil
	}
	line, err := bufio.NewReader(io.LimitReader(in, auth.MaxPasswordLen+2)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
