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
)

func runReconstruct(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reconstruct", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifest := fs.String("manifest", "", "fixed wbft-reconstruction-input/1 source manifest")
	from := fs.String("from", "", "first active height, as a full decimal integer")
	to := fs.String("to", "", "last active height, as a full decimal integer (at most 10000 heights)")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *manifest == "" || *from == "" || *to == "" {
		fs.Usage()
		return exitUsage
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	m, err := reconstruct.LoadManifest(ctx, *manifest)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	result, err := reconstruct.Assess(ctx, m, *from, *to)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if enc.Encode(result) != nil {
		return exitInternal
	}
	return exitOK
}
