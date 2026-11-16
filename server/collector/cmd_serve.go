package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/config"
	"github.com/erwsim/android-telemetry/server/collector/internal/export"
	"github.com/erwsim/android-telemetry/server/collector/internal/pki"
	"github.com/erwsim/android-telemetry/server/collector/internal/server"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
	"github.com/erwsim/android-telemetry/server/collector/web"
)

func cmdServe(args []string) error {
	fl := flag.NewFlagSet("serve", flag.ContinueOnError)
	if err := fl.Parse(args); err != nil {
		return err
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	log := newLogger(os.Stderr)
	ctx := context.Background()

	st, err := store.Open(ctx, cfg.DBPath())
	if err != nil {
		return fmt.Errorf("base de données %s : %w", cfg.DBPath(), err)
	}
	defer st.Close()

	if _, created, err := pki.LoadOrCreate(cfg.PKIDir(), time.Now()); err != nil {
		return fmt.Errorf("PKI : %w", err)
	} else if created {
		log.Info("AC cliente créée", "cert", filepath.Join(cfg.PKIDir(), "ca.crt"))
	}
	if n, err := st.CountUsers(ctx); err == nil && n == 0 {
		log.Warn("aucun compte console : créez-en un avec « vigie-collector user set-password <nom> »")
	}
	if !cfg.CookieSecure {
		log.Warn("VIGIE_COOKIE_SECURE=false : cookies de session sans attribut Secure (développement uniquement)")
	}
	if !cfg.RequireClientCert {
		log.Warn("VIGIE_REQUIRE_CLIENT_CERT=false : le certificat client n'est pas exigé à l'ingestion")
	}

	var consoleFS fs.FS
	if cfg.ConsoleDir != "" {
		if _, err := os.Stat(filepath.Join(cfg.ConsoleDir, "index.html")); err != nil {
			return fmt.Errorf("VIGIE_CONSOLE_DIR : index.html introuvable dans %s", cfg.ConsoleDir)
		}
		consoleFS = os.DirFS(cfg.ConsoleDir)
		log.Info("console servie depuis un répertoire", "dir", cfg.ConsoleDir)
	} else {
		var built bool
		consoleFS, built = web.Console()
		if !built {
			log.Warn("console non intégrée au binaire : page de substitution servie")
		}
	}

	bg, stopBg := context.WithCancel(ctx)
	defer stopBg()
	var exp *export.Exporter
	if cfg.ExportPath != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.ExportPath), 0o750); err != nil {
			return fmt.Errorf("répertoire d'export : %w", err)
		}
		exp = export.New(st, cfg.ExportPath, cfg.ExportMaxBytes, cfg.ExportKeep, log)
		if err := exp.Init(ctx); err != nil {
			return fmt.Errorf("export : %w", err)
		}
		go exp.Run(bg)
		log.Info("export NDJSON actif", "path", cfg.ExportPath, "max_bytes", cfg.ExportMaxBytes, "keep", cfg.ExportKeep)
	}

	srv, err := server.New(cfg, st, log, server.Options{Exporter: exp, ConsoleFS: consoleFS})
	if err != nil {
		return err
	}
	go srv.RunRetention(bg, time.Hour)
	go srv.RunCommands(bg)
	srv.StartTracking(bg)
	srv.StartDetections(bg)

	// Requests keep their own context until Shutdown has drained them.
	reqCtx, cancelReq := context.WithCancel(ctx)
	defer cancelReq()
	httpSrv := srv.NewHTTPServer(reqCtx)
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Info("vigie-collector démarré", "version", version, "listen", ln.Addr().String(), "data_dir", cfg.DataDir)

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.Serve(ln) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Info("arrêt demandé", "signal", s.String())
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	srv.CloseStreams()
	shCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shCtx); err != nil {
		log.Warn("arrêt HTTP incomplet", "err", err)
	}
	cancelReq()
	stopBg()
	if exp != nil {
		exp.Wait()
	}
	log.Info("vigie-collector arrêté")
	return nil
}

func cmdHealthcheck(args []string) error {
	fl := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	u := fl.String("url", "", "URL à vérifier (défaut : http://127.0.0.1:<port de VIGIE_LISTEN>/healthz)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	target := *u
	if target == "" {
		listen := os.Getenv("VIGIE_LISTEN")
		if listen == "" {
			listen = ":8080"
		}
		_, port, err := net.SplitHostPort(listen)
		if err != nil {
			return fmt.Errorf("VIGIE_LISTEN invalide : %w", err)
		}
		target = "http://127.0.0.1:" + port + "/healthz"
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(target)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s : HTTP %d", target, resp.StatusCode)
	}
	return nil
}
