package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	name := fs.String("dataset", "", "exact dataset name")
	out := fs.String("out", "", "new output directory; never overwritten")
	target := fs.String("target", "private", "destination classification: private or public")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 0 || *dsn == "" || *name == "" || *out == "" || (*target != "public" && *target != "private") {
		fmt.Fprintln(stderr, "Usage: wbft-analyzer export --db DSN --dataset NAME --out DIR [--target private|public]")
		return exitUsage
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	s, err := store.Open(ctx, *dsn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUnavailable
	}
	defer s.Close()
	if _, err = s.Migrate(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return exitInternal
	}
	result, err := s.ExportDataset(ctx, *name, *out, *target)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	if err = json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, err)
		return exitInternal
	}
	return exitOK
}
