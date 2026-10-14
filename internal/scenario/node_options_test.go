package scenario

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
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
	// Simulator directory names omit the hexadecimal prefix.
	path := filepath.Join(dir, address.Hex()[2:])
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
