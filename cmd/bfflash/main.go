// Command bfflash is a standalone Backend-for-Frontend driven by one YAML file.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bfflash/internal/config"
	"bfflash/internal/server"
)

const usage = `bfflash: a zero-code Backend-for-Frontend

Usage:
  bfflash serve    [-c bfflash.yaml]   run the server, reloading on config changes
  bfflash validate [-c bfflash.yaml]   check the config and exit
  bfflash routes   [-c bfflash.yaml]   print every path with its effective settings
`

const shutdownGrace = 20 * time.Second

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	file := fs.String("c", "bfflash.yaml", "config file")
	fs.Parse(os.Args[2:])

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(*file, log)
	case "validate":
		err = validate(*file, log)
	case "routes":
		err = routes(*file)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bfflash:", err)
		os.Exit(1)
	}
}

func validate(file string, log *slog.Logger) error {
	cfg, err := config.Load(file)
	if err != nil {
		return err
	}
	deps, err := server.NewDeps(cfg, log)
	if err != nil {
		return err
	}
	defer deps.Store.Close()
	if _, err := server.Compile(cfg, deps); err != nil {
		return err
	}
	fmt.Println("config ok")
	return nil
}

func routes(file string) error {
	cfg, err := config.Load(file)
	if err != nil {
		return err
	}
	cfg.Describe(os.Stdout)
	return nil
}

func serve(file string, log *slog.Logger) error {
	cfg, err := config.Load(file)
	if err != nil {
		return err
	}
	deps, err := server.NewDeps(cfg, log)
	if err != nil {
		return err
	}
	defer deps.Store.Close()
	srv, err := server.New(cfg, deps)
	if err != nil {
		return err
	}
	if cfg.OIDC != nil && cfg.Session.Store == "memory" {
		log.Warn("sessions are in memory: a restart logs everyone out, and replicas can't share them")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = config.Watch(ctx, file, func() {
		next, err := config.Load(file)
		if err == nil {
			err = srv.Reload(next)
		}
		if err != nil {
			log.Error("config reload rejected, keeping the running config", "err", err)
			return
		}
		log.Info("config reloaded")
	})
	if err != nil {
		log.Warn("config watch unavailable", "err", err)
	}
	go sweep(ctx, deps, log)

	hs := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Server.Listen)
		errc <- hs.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func sweep(ctx context.Context, deps *server.Deps, log *slog.Logger) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := deps.Store.Sweep(ctx); err != nil {
				log.Warn("session sweep failed", "err", err)
			}
		}
	}
}
