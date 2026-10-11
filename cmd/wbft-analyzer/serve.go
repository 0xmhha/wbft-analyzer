package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/api"
	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

const serveUsage = `Usage: wbft-analyzer serve --db DSN [--listen 127.0.0.1:8080] [--auth token]

Serves the REST API under /v1: networks, inspector reports with their
results and observations, observation trends, alert rules and alerts.
POST /v1/reports loads a report as "ingest reports" does.

The server listens on 127.0.0.1 by default and then needs no
authentication; it answers only to a loopback host name. To listen on any
other address it needs --auth token: every request must then carry
"Authorization: Bearer TOKEN", with TOKEN (32 characters or more) taken
from $WBFT_ANALYZER_TOKEN. The server speaks plain HTTP; put a TLS proxy in
front of it when it is reached over a network.

Exit codes: 0 stopped by a signal, 64 usage error, 69 the database is
unavailable or --auth oidc (not available yet), 70 the server failed.
`

func runServe(args []string, _, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, serveUsage); fs.PrintDefaults() }
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN (default $WBFT_ANALYZER_DB)")
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	auth := fs.String("auth", "", `authentication: "token" (bearer token from $WBFT_ANALYZER_TOKEN)`)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dsn == "" || fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}
	var token string
	switch *auth {
	case "":
		if !api.Loopback(*listen) {
			fmt.Fprintf(stderr, "wbft-analyzer serve: %s is not a loopback address; listening on it needs --auth token\n", *listen)
			return exitUsage
		}
	case "token":
		token = os.Getenv("WBFT_ANALYZER_TOKEN")
		if len(token) < api.MinTokenLen {
			fmt.Fprintf(stderr, "wbft-analyzer serve: --auth token needs $WBFT_ANALYZER_TOKEN of %d characters or more\n", api.MinTokenLen)
			return exitUsage
		}
	case "oidc":
		fmt.Fprintln(stderr, "wbft-analyzer serve: --auth oidc is not available yet in this version")
		return exitUnavailable
	default:
		fmt.Fprintf(stderr, "wbft-analyzer serve: unknown --auth %q\n", *auth)
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := store.Open(ctx, *dsn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUnavailable
	}
	defer s.Close()
	if _, err := s.Migrate(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return exitInternal
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	srv := &http.Server{
		Handler:           (&api.Server{Store: s, Reporter: &ingest.Reporter{Store: s}, Token: token, Log: log}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitInternal
	}
	log.Info("serving", "addr", ln.Addr().String(), "auth", *auth != "")
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case err := <-done:
		fmt.Fprintln(stderr, err)
		return exitInternal
	case <-ctx.Done():
	}
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shut); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintln(stderr, err)
		return exitInternal
	}
	return exitOK
}
