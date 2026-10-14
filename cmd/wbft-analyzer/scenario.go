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

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/scenariojob"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runScenario(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "fit" {
		fmt.Fprintln(stderr, "usage: wbft-analyzer scenario fit --db DSN --dataset ID --chain FILE --origin TIME --from N --to M")
		return exitUsage
	}
	fs := flag.NewFlagSet("scenario fit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", "", "PostgreSQL DSN; default from WBFT_ANALYZER_DB")
	dataset := fs.Int64("dataset", 0, "retained message dataset ID")
	chain := fs.String("chain", "", "canonical chain.rlp")
	events := fs.String("events-manifest", "", "native event manifest, if available")
	originText := fs.String("origin", "", "explicit RFC3339Nano scenario origin")
	from := fs.Uint64("from", 0, "first compared height")
	to := fs.Uint64("to", 0, "last compared height, with a retained child")
	until := fs.Duration("duration", time.Minute, "simulation duration, at most 24h")
	count := fs.Int("seeds", 32, "independent seeds, at most 128")
	wireMetric := fs.String("wire-metric", "link", "link (callback) or write_start_to_read_complete")
	clock := fs.String("clock", "unknown", "declared shared-host, ntp or unknown clock model")
	skew := fs.Int64("skew-ms", 0, "declared clock uncertainty in ms")
	timeout := fs.Duration("timeout", 5*time.Minute, "fitting deadline, at most 30m")
	parseErr := fs.Parse(args[1:])
	if *dsn == "" {
		*dsn = os.Getenv("WBFT_ANALYZER_DB")
	}
	if parseErr != nil || !scenario.ValidWireMetric(*wireMetric) || fs.NArg() != 0 || *dsn == "" || *dataset < 1 || *chain == "" || *from < 1 || *to < *from || *to-*from >= 10000 || *until <= 0 || *until > 24*time.Hour || *count < 2 || *count > 128 || *timeout <= 0 || *timeout > 30*time.Minute || *skew < 0 || *skew > 3600000 || *clock != "unknown" && *clock != "shared-host" && *clock != "ntp" {
		fs.Usage()
		return exitUsage
	}
	origin, err := time.Parse(time.RFC3339Nano, *originText)
	if err != nil {
		fmt.Fprintln(stderr, "explicit scenario origin required")
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	s, err := store.Open(ctx, *dsn)
	if err != nil {
		fmt.Fprintln(stderr, "scenario storage unavailable")
		return exitUnavailable
	}
	defer s.Close()
	seeds := make([]int64, *count)
	for i := range seeds {
		seeds[i] = int64(i + 1)
	}
	// Inspection reads existing retained inputs; it does not migrate the database.
	fitted, err := scenariojob.FitDataset(ctx, s, scenariojob.FitRequest{ChainPath: *chain, EventManifest: *events, Options: scenario.FitOptions{WireMetric: *wireMetric, Dataset: *dataset, Origin: origin, From: *from, To: *to, Until: *until, Seeds: seeds, Clock: pairs.Clock{Model: *clock, SkewMS: *skew}}})
	if err != nil {
		fmt.Fprintln(stderr, "scenario fitting unavailable for this source scope")
		return exitDataErr
	}
	if err := json.NewEncoder(stdout).Encode(fitted); err != nil {
		return exitInternal
	}
	if fitted.Model.Status != "complete" {
		fmt.Fprintln(stderr, "scenario model is incomplete; see recorded source issues")
		return exitDataErr
	}
	return exitOK
}
