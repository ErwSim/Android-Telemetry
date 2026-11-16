// Command vigie-collector is the Vigie collector: ingestion API, storage,
// console API, Wazuh NDJSON export, enrollment CLI and simulator.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `vigie-collector : collecteur de télémétrie Vigie

Utilisation :
  vigie-collector serve                                   démarre le serveur HTTP
  vigie-collector enroll --name <nom> --out <fichier.vigie> [--ingest-url URL] [--force]
  vigie-collector devices [--json]                        liste les appareils (expiration des certificats)
  vigie-collector renew <device_id> --out <fichier.vigie> [--ingest-url URL] [--force]
                                                          nouveau jeton et certificat, même appareil
  vigie-collector revoke <device_id>                      révoque un appareil
  vigie-collector user set-password <nom>                 crée ou modifie un compte console
                                                          (mot de passe lu sur l'entrée standard)
  vigie-collector sim --enroll <fichier.vigie> [--url URL] [--backfill 24h] [--follow] [--rate 1]
                      [--commands stream|poll|off] [--command-code CODE] [--fake-adguard 127.0.0.1:3001]
  vigie-collector healthcheck [--url URL]                 vérifie /healthz (HEALTHCHECK Docker)
  vigie-collector version

Configuration par variables d'environnement (VIGIE_DATA_DIR, VIGIE_LISTEN, …) : voir README.md.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "enroll":
		err = cmdEnroll(args)
	case "devices":
		err = cmdDevices(args)
	case "renew":
		err = cmdRenew(args)
	case "revoke":
		err = cmdRevoke(args)
	case "user":
		err = cmdUser(args)
	case "sim":
		err = cmdSim(args)
	case "healthcheck":
		err = cmdHealthcheck(args)
	case "version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "commande inconnue : %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
}

// newLogger returns a text logger on stderr; level from VIGIE_LOG_LEVEL.
func newLogger(w io.Writer) *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(os.Getenv("VIGIE_LOG_LEVEL")) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl}))
}
