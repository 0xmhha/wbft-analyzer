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
	"strings"
	"syscall"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runGovernance(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ingest governance", flag.ContinueOnError)
	// Flag errors can contain supplied credentials or arbitrary input.
	fs.SetOutput(io.Discard)
	dsn := fs.String("db", "", "PostgreSQL DSN (default $WBFT_ANALYZER_DB)")
	name := fs.String("name", "", "governance dataset name")
	path := fs.String("archive", "", "wbft-analyzer-governance/1 archive")
	url := fs.String("rpc", "", "read-only JSON-RPC URL (not persisted)")
	from := fs.String("from", "", "first canonical uint64 hex index (RPC)")
	to := fs.String("to", "", "last canonical uint64 hex index; at most 1024 indices (RPC)")
	rate := fs.Float64("rate", 2, "RPC requests/second, at most 5")
	var instances, proposals followList
	fs.Var(&instances, "instance", "historical state instance address (repeatable)")
	fs.Var(&proposals, "proposal", "proposal instance:hex-id; full history (repeatable)")
	usage := func() {
		fs.SetOutput(stderr)
		fmt.Fprintln(stderr, "Usage: wbft-analyzer ingest governance --db DSN --name NAME (--archive FILE | --rpc URL --from HEX --to HEX)")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			usage()
			return exitOK
		}
		fmt.Fprintln(stderr, "invalid governance arguments")
		return exitUsage
	}
	if *dsn == "" {
		*dsn = os.Getenv("WBFT_ANALYZER_DB")
	}
	if fs.NArg() != 0 || *dsn == "" || !logs.Identifier(*name) || (*path == "") == (*url == "") || *path != "" && (*from != "" || *to != "" || len(instances) > 0 || len(proposals) > 0) {
		fmt.Fprintln(stderr, "invalid governance input selection")
		return exitUsage
	}
	keys := []governance.ProposalKey{}
	for _, value := range proposals {
		parts := strings.Split(value, ":")
		if len(parts) != 2 {
			fmt.Fprintln(stderr, "invalid governance proposal scope")
			return exitUsage
		}
		keys = append(keys, governance.ProposalKey{Instance: parts[0], ID: parts[1]})
	}
	if *url != "" {
		if _, err := governance.Requests(*from, *to, instances, keys); err != nil {
			fmt.Fprintln(stderr, "invalid governance request scope")
			return exitUsage
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var archive governance.Archive
	var sha, kind string
	var err error
	if *path != "" {
		kind = "archive"
		archive, sha, err = governance.Load(*path)
	} else {
		kind = "rpc"
		var client *rpc.Client
		client, err = rpc.New(*url, *rate)
		if err == nil {
			archive, err = governance.Fetch(ctx, client, *from, *to, instances, keys)
		}
		if err == nil {
			var raw []byte
			raw, err = json.Marshal(archive)
			if err == nil {
				sum := sha256.Sum256(raw)
				sha = hex.EncodeToString(sum[:])
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "governance source could not be read")
		return exitDataErr
	}
	if _, err = governance.Normalize(archive); err != nil {
		fmt.Fprintln(stderr, "invalid governance capture")
		return exitDataErr
	}
	s, err := store.Open(ctx, *dsn)
	if err != nil {
		fmt.Fprintln(stderr, "governance database unavailable")
		return exitUnavailable
	}
	defer s.Close()
	if _, err = s.Migrate(ctx); err != nil {
		fmt.Fprintln(stderr, "governance schema migration failed")
		return exitInternal
	}
	result, err := ingest.Governance(ctx, s, *name, kind, sha, archive)
	if err != nil {
		fmt.Fprintln(stderr, "governance import failed")
		return exitDataErr
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "governance result could not be written")
		return exitInternal
	}
	return exitOK
}
