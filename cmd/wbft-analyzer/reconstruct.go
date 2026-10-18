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

	"github.com/0xmhha/wbft-analyzer/internal/reconstruct"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runReconstruct(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reconstruct", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifest := fs.String("manifest", "", "fixed wbft-reconstruction-input/1 source manifest")
	from := fs.String("from", "", "first active height, as a full decimal integer")
	to := fs.String("to", "", "last active height, as a full decimal integer (at most 10000 heights)")
	execute := fs.Bool("execute", false, "compare a closed processing capture using the linked WBFT core with all improvements disabled")
	review := fs.Int64("review-position", 0, "emit one reconstructed review packet at this comparison position; requires --execute")
	dsn := fs.String("db", "", "optionally store the closed execution in PostgreSQL")
	dataset := fs.Int64("dataset", 0, "completed log dataset for --db")
	input := fs.String("input", "", "exact original log input ID for --db")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *manifest == "" || *from == "" || *to == "" {
		fs.Usage()
		return exitUsage
	}
	if *review < 0 || *review > 0 && !*execute {
		fmt.Fprintln(stderr, "review position requires --execute and a positive comparison position")
		return exitUsage
	}
	if (*dsn != "" || *dataset != 0 || *input != "") && (*dsn == "" || *dataset < 1 || !logs.Identifier(*input) || !*execute) {
		fmt.Fprintln(stderr, "storage requires --execute, --db, --dataset and --input together")
		return exitUsage
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	m, err := reconstruct.LoadManifest(ctx, *manifest)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	var database *store.Store
	if *dsn != "" {
		database, err = store.Open(ctx, *dsn)
		if err != nil {
			fmt.Fprintln(stderr, "reconstruction database unavailable")
			return exitUnavailable
		}
		defer database.Close()
		if _, err = database.Migrate(ctx); err != nil {
			fmt.Fprintln(stderr, "reconstruction migration failed")
			return exitInternal
		}
		release, leaseErr := database.DatasetReadLease(ctx, *dataset)
		if leaseErr != nil {
			fmt.Fprintln(stderr, "reconstruction log dataset unavailable")
			return exitDataErr
		}
		defer release()
	}
	var result any
	if *execute {
		result, err = reconstruct.Execute(ctx, m, *from, *to)
	} else {
		result, err = reconstruct.Assess(ctx, m, *from, *to)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	output := result
	if *review > 0 {
		output, err = reconstruct.ExecutionReview(result.(reconstruct.ExecutionResult), *review)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitDataErr
		}
	}
	if database != nil {
		id, saveErr := database.PutReconstruction(ctx, *dataset, *input, result.(reconstruct.ExecutionResult))
		if saveErr != nil {
			fmt.Fprintln(stderr, "reconstruction result refused by storage")
			return exitDataErr
		}
		fmt.Fprintf(stderr, "stored reconstruction %d\n", id)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if enc.Encode(output) != nil {
		return exitInternal
	}
	return exitOK
}
