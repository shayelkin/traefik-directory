package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const shutdownTimeout = 5 * time.Second

func run(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	cfg, err := configFromEnv(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Handler:           newHandler(cfg, &http.Client{Timeout: 5 * time.Second}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      2 * apiTimeout,
		IdleTimeout:       60 * time.Second,
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("listening on %s, traefik api %s, entrypoints %s", cfg.Listen, cfg.APIURL, strings.Join(cfg.EntryPoints, ","))
	if err := run(ctx, srv, ln); err != nil {
		log.Fatal(err)
	}
}
