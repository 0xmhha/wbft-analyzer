package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runMessages(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ingest messages", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	path := fs.String("manifest", "", "wbft-analyzer-messages/1 manifest")
	if fs.Parse(args) != nil || *dsn == "" || *path == "" || fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}
	m, e := messages.LoadManifest(*path)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return exitDataErr
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	s, e := store.Open(ctx, *dsn)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return exitUnavailable
	}
	defer s.Close()
	if _, e = s.Migrate(ctx); e != nil {
		fmt.Fprintln(stderr, e)
		return exitInternal
	}
	res, e := ingest.Messages(ctx, s, m)
	if je := json.NewEncoder(stdout).Encode(res); je != nil {
		fmt.Fprintln(stderr, je)
		return exitInternal
	}
	if e != nil {
		fmt.Fprintln(stderr, e)
		return exitDataErr
	}
	return exitOK
}
