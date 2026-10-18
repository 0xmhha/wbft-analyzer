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
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runExecutionWitness(args []string, stdout, stderr io.Writer) int {
	return runExecutionWitnessMode(args, stdout, stderr, false)
}

func runGovernanceTransitions(args []string, stdout, stderr io.Writer) int {
	return runExecutionWitnessMode(args, stdout, stderr, true)
}

func runExecutionWitnessMode(args []string, stdout, stderr io.Writer, transitions bool) int {
	command := "execution-witness"
	if transitions {
		command = "governance-transitions"
	}
	fs := flag.NewFlagSet("ingest "+command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dsn := fs.String("db", "", "PostgreSQL DSN (default $WBFT_ANALYZER_DB)")
	dataset := fs.Int64("dataset-id", 0, "completed governance dataset ID")
	headers := fs.Int64("headers-dataset-id", 0, "completed canonical header dataset ID")
	manifest := fs.String("manifest", "", "checksummed execution witness manifest")
	directory := fs.String("root", "", "source directory containing every relative manifest file")
	helper := fs.String("helper", "", "operator-trusted WBFT execution helper binary")
	fingerprint := fs.String("helper-sha256", "", "operator-trusted binary SHA-256, independent of the manifest")
	timeout := fs.Duration("timeout", 5*time.Minute, "maximum verification time (up to 30m)")
	work := fs.String("work-dir", "", "directory for private temporary source and helper snapshots")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintf(stderr, "Usage: wbft-analyzer ingest %s --db DSN --dataset-id N --headers-dataset-id N --manifest FILE --root DIR --helper FILE --helper-sha256 SHA256\n", command)
			fs.SetOutput(stderr)
			fs.PrintDefaults()
			return exitOK
		}
		fmt.Fprintln(stderr, "invalid execution witness arguments")
		return exitUsage
	}
	if *dsn == "" {
		*dsn = os.Getenv("WBFT_ANALYZER_DB")
	}
	if fs.NArg() != 0 || *dsn == "" || *dataset < 1 || *headers < 1 || *dataset == *headers || *manifest == "" || *directory == "" || *helper == "" || *fingerprint == "" || *timeout <= 0 || *timeout > 30*time.Minute {
		fmt.Fprintln(stderr, "execution witness requires distinct completed datasets and original sources")
		return exitUsage
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	file, err := os.Open(*manifest)
	if err != nil {
		fmt.Fprintln(stderr, "execution manifest unavailable")
		return exitDataErr
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, executionwitness.MaxManifestBytes+1))
	_ = file.Close()
	if readErr != nil || len(raw) > executionwitness.MaxManifestBytes {
		fmt.Fprintln(stderr, "invalid execution manifest")
		return exitDataErr
	}
	root, err := os.OpenRoot(*directory)
	if err != nil {
		fmt.Fprintln(stderr, "execution source directory unavailable")
		return exitDataErr
	}
	defer root.Close()
	implementation := executionwitness.Helper{Path: *helper, SHA256: *fingerprint, Timeout: *timeout, WorkDir: *work}
	var persist func(context.Context, *store.Store) (any, error)
	if transitions {
		var bundle executionwitness.TransitionBundle
		bundle, err = executionwitness.LoadTransitions(ctx, raw, root, implementation)
		persist = func(ctx context.Context, s *store.Store) (any, error) {
			return s.PutGovernanceTransitions(ctx, *dataset, *headers, bundle)
		}
	} else {
		var bundle executionwitness.Bundle
		bundle, err = executionwitness.Load(ctx, raw, root, implementation)
		persist = func(ctx context.Context, s *store.Store) (any, error) {
			return s.PutGovernanceExecutionWitness(ctx, *dataset, *headers, bundle)
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "execution original sources could not be authenticated")
		return exitDataErr
	}
	s, err := store.Open(ctx, *dsn)
	if err != nil {
		fmt.Fprintln(stderr, "execution database unavailable")
		return exitUnavailable
	}
	defer s.Close()
	if _, err = s.Migrate(ctx); err != nil {
		fmt.Fprintln(stderr, "execution schema migration failed")
		return exitInternal
	}
	result, err := persist(ctx, s)
	if err != nil {
		fmt.Fprintln(stderr, "execution witness has no matching available governance and header sources")
		return exitDataErr
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "execution result could not be written")
		return exitInternal
	}
	return exitOK
}
