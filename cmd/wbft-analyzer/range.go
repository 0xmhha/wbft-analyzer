package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runRange(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ingest range", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	endpoint := fs.String("rpc", "", "read-only RPC endpoint")
	blocks := fs.String("blocks", "", "directory of zero-padded block RLP files; alternative to RPC")
	config := fs.String("config", "", "genesis config JSON file (required; no preset assumptions)")
	from := fs.String("from", "", "first canonical index, decimal")
	to := fs.String("to", "", "last canonical index, decimal; the child is also fetched")
	name := fs.String("name", "", "dataset name, repeat to resume")
	node := fs.String("node", "", "node label (no credentials)")
	network := fs.String("network", "", "display name")
	rate := fs.Float64("rate", 5, "RPC batches per second, at most 5 (100 headers per batch)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	a, e1 := strconv.ParseUint(*from, 10, 64)
	b, e2 := strconv.ParseUint(*to, 10, 64)
	if *dsn == "" || *config == "" || *name == "" || *node == "" || (*endpoint == "") == (*blocks == "") || e1 != nil || e2 != nil || b < a || b == ^uint64(0) || b-a >= 1_000_000 || fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}
	raw, err := os.ReadFile(*config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	// Accept a genesis file as well as its config object.
	var g struct {
		Config json.RawMessage `json:"config"`
	}
	if json.Unmarshal(raw, &g) == nil && len(g.Config) > 0 {
		raw = g.Config
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	src := &headers.Source{Blocks: *blocks, Context: ctx}
	if *endpoint != "" {
		src.RPC, err = rpc.New(*endpoint, *rate)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
	}
	if src.RPC != nil {
		caps, e := src.RPC.Capabilities(ctx)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return exitUnavailable
		}
		for _, cap := range caps {
			fmt.Fprintf(stderr, "capability %s: %t\n", cap.Method, cap.Available)
		}
	}
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
	last := time.Now()
	result, err := ingest.Range(ctx, s, ingest.RangeOptions{Name: *name, Node: *node, NetworkName: *network, From: a, To: b, Config: raw, Source: src, Progress: func(n int64, d time.Duration) {
		if time.Since(last) >= 10*time.Second {
			fmt.Fprintf(stderr, "imported %d headers in %s\n", n, d.Round(time.Second))
			last = time.Now()
		}
	}})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	fmt.Fprintf(stdout, "dataset %d network %d: %d headers in %s (%.1f headers/s)\n", result.DatasetID, result.NetworkID, result.Headers, result.Elapsed.Round(time.Millisecond), float64(result.Headers)/result.Elapsed.Seconds())
	return exitOK
}
