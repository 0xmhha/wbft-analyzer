package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

const ingestUsage = `Usage: wbft-analyzer ingest reports --db DSN FILE ...

Loads wbft-inspector reports. Each file is read, checked by the public
build (public inspector build, public requirements, known catalog hash),
stored once (a file already stored is skipped), and its observation rates
are added to the trends of its network; the alert rules of that network
are evaluated and their webhooks told of state changes.

Use "ingest range -h" for RPC/RLP header range imports.
Use "ingest run -h" for node log datasets; events and node logs.
Use "ingest messages -h" for journal/R-01 message metadata datasets.
Use "ingest observe -h" for read-only native RPC observation datasets.

Exit codes: 0 every file added or skipped, 65 a file refused or not a
report, 69 the database is unavailable, 70 a store error.
`

// Exit codes beyond those of main.go (sysexits).
const (
	exitDataErr  = 65
	exitInternal = 70
)

func runIngest(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "observe" {
		return runObserve(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "messages" {
		return runMessages(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "run" {
		return runRun(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "range" {
		return runRange(args[1:], stdout, stderr)
	}
	if len(args) == 0 || args[0] != "reports" {
		fmt.Fprint(stderr, ingestUsage)
		return exitUsage
	}
	fs := flag.NewFlagSet("ingest reports", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, ingestUsage); fs.PrintDefaults() }
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN (default $WBFT_ANALYZER_DB)")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if *dsn == "" || fs.NArg() == 0 {
		fs.Usage()
		return exitUsage
	}
	ctx := context.Background()
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
	r := &ingest.Reporter{Store: s}
	results, err := r.Files(ctx, fs.Args())
	code := exitOK
	for _, x := range results {
		fmt.Fprintf(stdout, "%s %s %s: %s\n", x.Outcome, short(x.ID), x.File, x.Detail)
		for _, a := range x.Alerts {
			fmt.Fprintf(stdout, "  alert rule %d (%s %s): %s -> %s, recent %g, baseline %g\n", a.Rule, a.Kind, a.Node, a.Before, a.State,
				a.Recent, a.Baseline)
			if a.WebhookError != "" {
				fmt.Fprintf(stdout, "  webhook of rule %d failed: %s\n", a.Rule, a.WebhookError)
			}
		}
		if x.Outcome == ingest.Refused || x.Outcome == ingest.Invalid {
			code = exitDataErr
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitInternal
	}
	return code
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	if id == "" {
		return "-"
	}
	return id
}
