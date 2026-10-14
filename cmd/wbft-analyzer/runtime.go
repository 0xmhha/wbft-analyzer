package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runRuntime(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ingest runtime", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	name := fs.String("name", "", "new runtime dataset name")
	path := fs.String("file", "", "local runtime sidecar")
	chain := fs.String("chain-id", "", "declared network chain ID")
	genesis := fs.String("genesis", "", "declared network genesis hash")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *dsn == "" || *name == "" || *path == "" || !regexp.MustCompile(`^(0|[1-9][0-9]{0,155})$`).MatchString(*chain) || !regexp.MustCompile(`^0x[0-9a-f]{64}$`).MatchString(*genesis) {
		fs.Usage()
		return exitUsage
	}
	c, e := runtimeobs.Load(*path)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return exitDataErr
	}
	ctx := context.Background()
	s, e := store.Open(ctx, *dsn)
	if e != nil {
		fmt.Fprintln(stderr, "database unavailable")
		return exitUnavailable
	}
	defer s.Close()
	if _, e = s.Migrate(ctx); e != nil {
		fmt.Fprintln(stderr, e)
		return exitInternal
	}
	out, e := ingest.Runtime(ctx, s, store.NetworkKey{ChainID: *chain, GenesisHash: *genesis}, *name, c)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return exitDataErr
	}
	if json.NewEncoder(stdout).Encode(out) != nil {
		return exitInternal
	}
	return exitOK
}
