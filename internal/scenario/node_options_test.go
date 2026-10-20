package scenario

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestRecordedNodeOptionsFromOfficialJournal(t *testing.T) {
	nodes, links := completeFixture()
	delay := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, delay, delay, sim.Stop{Height: 2, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	res, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: dir})
	if err != nil || len(res.Violations) > 0 {
		t.Fatalf("run %v", err)
	}
	address := sc.Validators[0].Address()
	// Simulator directory names use lowercase bytes, not checksummed Hex names.
	path := filepath.Join(dir, hex.EncodeToString(address.Bytes()))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	exact := false
	for _, entry := range entries {
		exact = exact || entry.IsDir() && entry.Name() == filepath.Base(path)
	}
	if !exact {
		t.Fatal("journal path does not match the exact simulator directory name")
	}
	node, cfg, err := InspectNodeOptions(context.Background(), path, address)
	if err != nil {
		t.Fatal(err)
	}
	if node.Improvements != nodes[0].Improvements || node.Profile != "compat" || node.ReplayWAL || cfg.ConfigAt(types.HeightFromUint64(1)).RequestTimeoutMs != 2000 {
		t.Fatalf("node %+v", node)
	}
	if _, _, err := InspectNodeOptions(context.Background(), path, types.Address{19: 99}); err == nil {
		t.Fatal("wrong node accepted")
	}
	if _, _, err := InspectNodeOptions(context.Background(), t.TempDir(), address); err == nil {
		t.Fatal("empty journal accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := InspectNodeOptions(ctx, path, address); err == nil {
		t.Fatal("cancel ignored")
	}
}

func TestRecordedNodePolicyDefaultsAreExplicit(t *testing.T) {
	address := types.Address{1}
	for _, profile := range []string{"", journal.CheckedProposerPolicyProfile, "future"} {
		directory := t.TempDir()
		raw := []byte(`{"chainId":7,"anzeon":{"wbft":{"epochLength":10}}}`)
		writer, err := journal.Open(journal.Options{Dir: directory, Synchronous: true}, journal.Identity{Run: "synthetic-policy", Self: address, Core: journal.CoreOptions{Self: address, ChainConfig: raw, Profile: "compat", Improvements: uint64(consensus.RestartSafety), ProposerPolicyProfile: profile}})
		if err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		_, cfg, err := InspectNodeOptions(t.Context(), directory, address)
		if profile == "future" {
			if err == nil {
				t.Fatal("unknown recorded policy profile accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if profile == "" && cfg.Base().ProposerPolicy != nil {
			t.Fatal("legacy recording acquired a default")
		}
		if profile != "" && (cfg.Base().ProposerPolicy == nil || cfg.Base().ProposerPolicy.ID != 0) {
			t.Fatal("recorded default not applied")
		}
	}
}
