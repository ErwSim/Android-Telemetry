// Command watchpost-collector is the Watchpost collector: ingestion API, storage,
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

const usage = `watchpost-collector: Watchpost telemetry collector

Usage:
  watchpost-collector serve                                   start the HTTP server
  watchpost-collector enroll --name <name> --out <file.watchpost> [--ingest-url URL] [--force]
  watchpost-collector devices [--json]                        list devices (certificate expiry)
  watchpost-collector renew <device_id> --out <file.watchpost> [--ingest-url URL] [--force]
                                                          new token and certificate, same device
  watchpost-collector revoke <device_id>                      revoke a device
  watchpost-collector user set-password <name>                create or change a console account
                                                          (password read from standard input)
  watchpost-collector sim --enroll <file.watchpost> [--url URL] [--backfill 24h] [--follow] [--rate 1]
                      [--commands stream|poll|off] [--command-code PASSPHRASE] [--fake-adguard 127.0.0.1:3001]
  watchpost-collector healthcheck [--url URL]                 check /healthz (Docker HEALTHCHECK)
  watchpost-collector version

Configuration through environment variables (WATCHPOST_DATA_DIR, WATCHPOST_LISTEN, ...): see README.md.
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
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// newLogger returns a text logger on stderr; level from WATCHPOST_LOG_LEVEL.
func newLogger(w io.Writer) *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(os.Getenv("WATCHPOST_LOG_LEVEL")) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl}))
}
