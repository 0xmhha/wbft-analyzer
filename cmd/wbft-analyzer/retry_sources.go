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

	"github.com/0xmhha/wbft-analyzer/internal/source/retrysources"
	"github.com/0xmhha/wbft/observe/journal"
)

func runRetrySources(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("retry-sources", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	directory := fs.String("journal", "", "original journal directory")
	limitFile := fs.String("source-limits", "", "explicit offline inspection limits JSON file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, "Usage: wbft-analyzer retry-sources --journal DIR --source-limits FILE")
			return exitOK
		}
		fmt.Fprintln(stderr, "invalid retry source arguments")
		return exitUsage
	}
	if fs.NArg() != 0 || *directory == "" || *limitFile == "" {
		fmt.Fprintln(stderr, "retry sources require original journal and explicit limits")
		return exitUsage
	}
	file, err := os.Open(*limitFile)
	if err != nil {
		fmt.Fprintln(stderr, "retry source limits unavailable")
		return exitDataErr
	}
	raw, err := io.ReadAll(io.LimitReader(file, retrysources.MaxLimitsBytes+1))
	_ = file.Close()
	if err != nil {
		fmt.Fprintln(stderr, "retry source limits invalid")
		return exitDataErr
	}
	limits, err := retrysources.Limits(raw)
	if err != nil {
		fmt.Fprintln(stderr, "retry source limits invalid")
		return exitDataErr
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := retrysources.Check(ctx, *directory, limits)
	if err != nil && !errors.Is(err, journal.ErrRoundChangeRetrySource) {
		fmt.Fprintln(stderr, "retry source input unavailable or invalid")
		return exitDataErr
	}
	if encodeErr := json.NewEncoder(stdout).Encode(result); encodeErr != nil {
		fmt.Fprintln(stderr, "cannot write retry source result")
		return exitInternal
	}
	if err != nil || result.Status == "inconsistent" {
		return exitDataErr
	}
	if result.Status != "consistent" {
		return exitUnavailable
	}
	return exitOK
}
