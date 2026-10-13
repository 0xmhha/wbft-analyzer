package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runObserve(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ingest observe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	name := fs.String("name", "", "new observation dataset name")
	path := fs.String("archive", "", "wbft-analyzer-observe/1 local archive")
	url := fs.String("rpc", "", "read-only native JSON-RPC URL (not persisted)")
	from := fs.String("from", "", "first full decimal height (RPC)")
	to := fs.String("to", "", "last full decimal height (RPC)")
	rate := fs.Float64("rate", 2, "RPC batches/second, at most 5")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *dsn == "" || *name == "" || (*path == "") == (*url == "") || *path != "" && (*from != "" || *to != "") {
		fs.Usage()
		return exitUsage
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var a observe.Archive
	var sha, kind string
	var e error
	if *path != "" {
		kind = "archive"
		a, sha, e = observe.Load(*path)
	} else {
		kind = "rpc"
		var c *rpc.Client
		c, e = rpc.New(*url, *rate)
		if e == nil {
			a, e = observe.Fetch(ctx, c, *from, *to)
		}
		if e == nil {
			raw, err := json.Marshal(a)
			if err != nil {
				e = err
			} else {
				sum := sha256.Sum256(raw)
				sha = hex.EncodeToString(sum[:])
			}
		}
	}
	if e != nil {
		fmt.Fprintln(stderr, e)
		return exitDataErr
	}
	s, e := store.Open(ctx, *dsn)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return exitUnavailable
	}
	defer s.Close()
	if _, e = s.Migrate(ctx); e != nil {
		fmt.Fprintln(stderr, e)
		return exitInternal
	}
	result, e := ingest.Observations(ctx, s, *name, kind, sha, a)
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, err)
		return exitInternal
	}
	if e != nil {
		fmt.Fprintln(stderr, e)
		return exitDataErr
	}
	return exitOK
}
