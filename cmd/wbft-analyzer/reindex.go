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
	if len(args) == 0 || args[0] != "replay" && args[0] != "messages" {
		fmt.Fprintln(stderr, "Usage: wbft-analyzer reindex replay|messages --db DSN --dataset ID")
		return exitUsage
	}
	fs := flag.NewFlagSet("reindex "+args[0], flag.ContinueOnError)
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
	if args[0] == "messages" {
		out, e := s.RebuildMessagePairs(ctx, *id)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return exitDataErr
		}
		fmt.Fprintf(stdout, "dataset=%d records=%d pairs=%d issues=%d version=%s\n", *id, out.Records, out.Pairs, out.Issues, out.Version)
		return exitOK
	}
	out, err := s.RebuildReplay(ctx, *id)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	fmt.Fprintf(stdout, "dataset=%d records=%d keyframes=%d version=%s\n", *id, out.Records, out.Frames, out.Version)
	return exitOK
}
