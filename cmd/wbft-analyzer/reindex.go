package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"io"
	"os"
)

func runReindex(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "replay" {
		fmt.Fprintln(stderr, "Usage: wbft-analyzer reindex replay --db DSN --dataset ID")
		return exitUsage
	}
	fs := flag.NewFlagSet("reindex replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	id := fs.Int64("dataset", 0, "run dataset ID")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *dsn == "" || *id <= 0 {
		return exitUsage
	}
	ctx := context.Background()
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
	out, err := s.RebuildReplay(ctx, *id)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	fmt.Fprintf(stdout, "dataset=%d records=%d keyframes=%d version=%s\n", *id, out.Records, out.Frames, out.Version)
	return exitOK
}
