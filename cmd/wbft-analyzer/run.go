package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ingest run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	manifest := fs.String("manifest", "", "wbft-analyzer-run/1 manifest file")
	workspace := fs.String("chainbench", "", "local chainbench formatVersion 3 workspace (network identity from --rpc)")
	endpoint := fs.String("rpc", "", "RPC endpoint for chainbench network identity")
	profile := fs.String("profile", "gstable@740526d03", "chainbench log profile: legacy ID, wbft, or file")
	name := fs.String("name", "", "chainbench dataset name")
	run := fs.String("run", "", "chainbench run label (defaults to dataset name)")
	network := fs.String("network", "", "chainbench network display name")
	clock := fs.String("clock", "unknown", "chainbench clock model: unknown, shared-host, ntp")
	from := fs.String("from_t", "", "optional inclusive RFC3339 window start")
	to := fs.String("to_t", "", "optional inclusive RFC3339 window end")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dsn == "" || fs.NArg() != 0 || (*manifest == "") == (*workspace == "") {
		fs.Usage()
		return exitUsage
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var m logs.Manifest
	var err error
	if *manifest != "" {
		if *endpoint != "" || *name != "" || *from != "" || *to != "" {
			fmt.Fprintln(stderr, "manifest mode takes identity and time bounds from the file")
			return exitUsage
		}
		m, err = logs.LoadManifest(*manifest)
	} else {
		if *endpoint == "" || *name == "" {
			fmt.Fprintln(stderr, "chainbench mode needs --rpc and --name")
			return exitUsage
		}
		client, e := rpc.New(*endpoint, 5)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return exitUsage
		}
		var id string
		err = client.Call(ctx, &id, "eth_chainId")
		var block struct {
			Hash string `json:"hash"`
		}
		if err == nil {
			err = client.Call(ctx, &block, "eth_getBlockByNumber", "0x0", false)
		}
		if err == nil {
			var number json.Number
			// RPC chain IDs are hex quantities; use a full integer instead of float.
			number, err = chainID(id)
			if err == nil {
				if *run == "" {
					*run = *name
				}
				m, err = logs.Chainbench(*workspace, *name, *run, *profile, logs.Network{ChainID: number.String(), GenesisHash: block.Hash, Name: *network})
				m.Clock = *clock
				m.FromWall = *from
				m.ToWall = *to
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
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
	res, err := ingest.Run(ctx, s, m, func(n int64) {
		if n%10000 == 0 {
			fmt.Fprintf(stderr, "normalized %d events\n", n)
		}
	})
	for _, in := range res.Inputs {
		fmt.Fprintf(stdout, "%s node=%s bytes=%d events=%d unknown=%d malformed=%d clock_regressions=%d sha256=%s\n", in.ID, in.Node, in.Bytes, in.Stats.Events, in.Stats.Unknown, in.Stats.Malformed, in.Stats.ClockRegressions, in.SHA256)
	}
	fmt.Fprintf(stdout, "dataset=%d network=%d stored_events=%d skipped=%t elapsed=%s\n", res.DatasetID, res.NetworkID, res.Events, res.Skipped, res.Elapsed)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	return exitOK
}

func chainID(hex string) (json.Number, error) {
	if !strings.HasPrefix(hex, "0x") {
		return "", fmt.Errorf("invalid RPC chain ID")
	}
	n, ok := new(big.Int).SetString(hex[2:], 16)
	if !ok || n.Sign() < 0 || n.BitLen() > 512 {
		return "", fmt.Errorf("invalid RPC chain ID")
	}
	return json.Number(n.String()), nil
}
