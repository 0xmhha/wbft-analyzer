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

	"github.com/0xmhha/wbft-analyzer/internal/source/failuresources"
	"github.com/0xmhha/wbft/observe/journal"
)

func runReceiveFailures(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("receive-failures", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	directory := fs.String("journal", "", "original journal directory")
	limitFile := fs.String("source-limits", "", "explicit offline inspection limits JSON file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, "Usage: wbft-analyzer receive-failures --journal DIR --source-limits FILE")
			return exitOK
		}
		fmt.Fprintln(stderr, "invalid receive failure source arguments")
		return exitUsage
	}
	if fs.NArg() != 0 || *directory == "" || *limitFile == "" {
		fmt.Fprintln(stderr, "receive failures require original journal and explicit limits")
		return exitUsage
	}
	file, err := os.Open(*limitFile)
	if err != nil {
		fmt.Fprintln(stderr, "receive failure source limits unavailable")
		return exitDataErr
	}
	raw, err := io.ReadAll(io.LimitReader(file, failuresources.MaxLimitsBytes+1))
	_ = file.Close()
	if err != nil {
		fmt.Fprintln(stderr, "receive failure source limits invalid")
		return exitDataErr
	}
	limits, err := failuresources.Limits(raw)
	if err != nil {
		fmt.Fprintln(stderr, "receive failure source limits invalid")
		return exitDataErr
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := failuresources.Check(ctx, *directory, limits)
	if err != nil && !errors.Is(err, journal.ErrReceiveFailureSource) {
		fmt.Fprintln(stderr, "receive failure source input unavailable or invalid")
		return exitDataErr
	}
	if encodeErr := json.NewEncoder(stdout).Encode(result); encodeErr != nil {
		fmt.Fprintln(stderr, "cannot write receive failure source result")
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
