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

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
	"github.com/0xmhha/wbft-analyzer/internal/whatifjob"
)

func runWhatif(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("whatif", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	dataset := fs.Int64("dataset", 0, "message dataset ID")
	input := fs.String("input", "", "retained complete journal input ID")
	chain := fs.String("chain", "", "recorded canonical chain.rlp")
	policyFile := fs.String("timer-policy", "", "explicit counterfactual timer policy JSON file")
	timeout := fs.Duration("timeout", 5*time.Minute, "experiment deadline, at most 30m")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *dsn == "" || *dataset < 1 || !logs.Identifier(*input) || *chain == "" || *policyFile == "" || *timeout <= 0 || *timeout > 30*time.Minute {
		fs.Usage()
		return exitUsage
	}
	file, err := os.Open(*policyFile)
	if err != nil {
		return exitUsage
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	_ = file.Close()
	var policy whatif.Policy
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &policy) != nil {
		fmt.Fprintln(stderr, "invalid timer policy")
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	s, err := store.Open(ctx, *dsn)
	if err != nil {
		fmt.Fprintln(stderr, "experiment storage unavailable")
		return exitUnavailable
	}
	defer s.Close()
	if _, err = s.Migrate(ctx); err != nil {
		fmt.Fprintln(stderr, "experiment migration failed")
		return exitInternal
	}
	result, err := whatifjob.Run(ctx, s, whatifjob.Options{Dataset: *dataset, Input: *input, Chain: *chain, Policy: policy})
	if result.ID == 0 {
		fmt.Fprintln(stderr, "experiment input unavailable")
		return exitDataErr
	}
	if encodeErr := json.NewEncoder(stdout).Encode(result); encodeErr != nil {
		return exitInternal
	}
	if err != nil {
		fmt.Fprintln(stderr, "experiment is incomplete; see recorded failure and horizon")
		return exitDataErr
	}
	return exitOK
}
