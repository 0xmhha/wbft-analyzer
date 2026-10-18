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

	"github.com/0xmhha/wbft-analyzer/internal/source/statewitness"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runStateWitness(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ingest state-witness", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dsn := fs.String("db", "", "PostgreSQL DSN (default $WBFT_ANALYZER_DB)")
	dataset := fs.Int64("dataset-id", 0, "completed governance dataset ID")
	headers := fs.Int64("headers-dataset-id", 0, "completed canonical header dataset ID")
	manifest := fs.String("manifest", "", "checksummed execution-state witness manifest")
	directory := fs.String("root", "", "source directory containing every relative manifest file")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(stderr, "Usage: wbft-analyzer ingest state-witness --db DSN --dataset-id N --headers-dataset-id N --manifest FILE --root DIR")
			fs.SetOutput(stderr)
			fs.PrintDefaults()
			return exitOK
		}
		fmt.Fprintln(stderr, "invalid execution-state witness arguments")
		return exitUsage
	}
	if *dsn == "" {
		*dsn = os.Getenv("WBFT_ANALYZER_DB")
	}
	if fs.NArg() != 0 || *dsn == "" || *dataset < 1 || *headers < 1 || *dataset == *headers || *manifest == "" || *directory == "" {
		fmt.Fprintln(stderr, "execution-state witness requires distinct completed datasets and original sources")
		return exitUsage
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	file, err := os.Open(*manifest)
	if err != nil {
		fmt.Fprintln(stderr, "execution-state manifest unavailable")
		return exitDataErr
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, statewitness.MaxManifestBytes+1))
	_ = file.Close()
	if readErr != nil || len(raw) > statewitness.MaxManifestBytes {
		fmt.Fprintln(stderr, "invalid execution-state manifest")
		return exitDataErr
	}
	root, err := os.OpenRoot(*directory)
	if err != nil {
		fmt.Fprintln(stderr, "execution-state source directory unavailable")
		return exitDataErr
	}
	defer root.Close()
	bundle, err := statewitness.Load(ctx, raw, root)
	if err != nil {
		fmt.Fprintln(stderr, "execution-state original sources could not be authenticated")
		return exitDataErr
	}
	s, err := store.Open(ctx, *dsn)
	if err != nil {
		fmt.Fprintln(stderr, "execution-state database unavailable")
		return exitUnavailable
	}
	defer s.Close()
	if _, err = s.Migrate(ctx); err != nil {
		fmt.Fprintln(stderr, "execution-state schema migration failed")
		return exitInternal
	}
	result, err := s.PutGovernanceStateWitness(ctx, *dataset, *headers, bundle)
	if err != nil {
		fmt.Fprintln(stderr, "execution-state witness has no matching available governance and header sources")
		return exitDataErr
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "execution-state result could not be written")
		return exitInternal
	}
	return exitOK
}
