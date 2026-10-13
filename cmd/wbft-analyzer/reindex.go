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
	if len(args) == 0 || args[0] != "replay" && args[0] != "messages" && args[0] != "missing" && args[0] != "observations" {
		fmt.Fprintln(stderr, "Usage: wbft-analyzer reindex replay|messages|missing|observations --db DSN --dataset ID")
		return exitUsage
	}
	fs := flag.NewFlagSet("reindex "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	id := fs.Int64("dataset", 0, "run dataset ID")
	from := fs.Uint64("from", 0, "first canonical index for missing classification")
	to := fs.Uint64("to", 0, "last canonical index for missing classification")
	messages := fs.Int64("messages", 0, "verified journal companion for missing classification")
	events := fs.Int64("events", 0, "explicit native event dataset for journal association")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *dsn == "" || *id <= 0 || *events < 0 || args[0] != "messages" && *events != 0 || *messages < 0 || args[0] != "missing" && (*messages != 0 || *from != 0 || *to != 0) {
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
	if args[0] == "observations" {
		out, e := s.RebuildObservationHeaders(ctx, *id)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return exitDataErr
		}
		fmt.Fprintf(stdout, "dataset=%d rows=%d bound_copies=%d snapshot=%s version=%s\n", *id, out.Rows, out.BoundCopies, out.Snapshot, out.Version)
		return exitOK
	}
	if args[0] == "missing" {
		provided := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
		if !provided["from"] || !provided["to"] {
			return exitUsage
		}
		out, e := s.RebuildMissing(ctx, *id, *messages, *from, *to)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return exitDataErr
		}
		fmt.Fprintf(stdout, "dataset=%d cells=%d from=%s to=%s snapshot=%s version=%s\n", *id, out.Cells, out.From, out.To, out.Snapshot, out.Version)
		return exitOK
	}
	if args[0] == "messages" {
		var refs []int64
		if *events > 0 {
			refs = append(refs, *events)
		}
		out, e := s.RebuildMessagePairs(ctx, *id, refs...)
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
