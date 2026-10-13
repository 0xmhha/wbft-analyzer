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
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/replayjob"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runReexecHelper(_ []string, stdout, stderr io.Writer) int {
	if err := reexec.Serve(context.Background(), os.Stdin, stdout); err != nil {
		fmt.Fprintln(stderr, "replay helper failed")
		return exitDataErr
	}
	return exitOK
}

func runReexec(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reexec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	dataset := fs.Int64("dataset", 0, "message dataset ID")
	input := fs.String("input", "", "retained journal input ID")
	chain := fs.String("chain", "", "recorded canonical chain.rlp")
	from := fs.Uint64("from", 0, "first active height (inclusive)")
	to := fs.Uint64("to", 0, "last active height (inclusive)")
	omit := fs.Bool("omit-missing-captures", false, "counterfactual: omit missing referenced received inputs")
	helper := fs.String("helper", "", "versioned wbft-replay executable; default: linked core in a child")
	timeout := fs.Duration("timeout", 5*time.Minute, "helper deadline, at most 30m")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *dsn == "" || *dataset < 1 || !logs.Identifier(*input) || *chain == "" || *from < 1 || *to < *from || *to-*from >= 10000 || *timeout <= 0 || *timeout > 30*time.Minute {
		fs.Usage()
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

	executable := *helper
	helperArgs := []string{}
	if executable == "" {
		executable, err = os.Executable()
		helperArgs = []string{"reexec-helper"}
	}
	if err != nil {
		return exitInternal
	}
	result, runErr := replayjob.Run(ctx, s, replayjob.RunOptions{Dataset: *dataset, Input: *input, Chain: *chain, From: *from, To: *to, Helper: reexec.Helper{Path: executable, Args: helperArgs, Timeout: *timeout, OmitMissing: *omit}}, nil)
	if errors.Is(runErr, replayjob.ErrStore) {
		fmt.Fprintln(stderr, "replay storage failed")
		return exitInternal
	}
	if result.ID == 0 {
		fmt.Fprintln(stderr, "replay input unavailable")
		return exitDataErr
	}
	if e := json.NewEncoder(stdout).Encode(result); e != nil {
		return exitInternal
	}
	if runErr != nil {
		fmt.Fprintln(stderr, "replay failed; see source completeness and helper status")
		return exitDataErr
	}
	return exitOK
}
