package scenario

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

func TestOfficialSimulatorSeedOutputs(t *testing.T) {
	keys, err := TestValidators([]types.Address{{19: 3}, {19: 1}, {19: 4}, {19: 2}})
	if err != nil {
		t.Fatal(err)
	}
	sc := sim.Scenario{Validators: keys, Until: sim.Stop{Height: 3, Duration: time.Minute}}
	collect := func() []SeedResult {
		out := []SeedResult{}
		err := RunSeeds(context.Background(), sc, []int64{1, 2}, 1, 3, func(r SeedResult) error { out = append(out, r); return nil })
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	got := collect()
	if len(got) != 2 || got[0].Status != "complete" || len(got[0].Heights) != 3 {
		t.Fatalf("run %+v", got)
	}
	if got[0].Execution == nil || len(got[0].Execution.Nodes) != 4 || len(got[0].Execution.Violations) != 0 || got[0].Execution.StopHeight != 3 {
		t.Fatal("official execution diagnostics not forwarded", got[0])
	}
	if !reflect.DeepEqual(got, collect()) {
		t.Fatal("seed outputs changed")
	}
	sc.Until = sim.Stop{Height: 1, Duration: time.Second}
	err = RunSeeds(context.Background(), sc, []int64{1}, 1, 3, func(r SeedResult) error {
		if r.Status != "partial" {
			t.Fatal("unfinished run marked complete")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop")
	if err := RunSeeds(context.Background(), sc, []int64{1}, 1, 3, func(SeedResult) error { return stop }); !errors.Is(err, stop) {
		t.Fatal("emit error ignored")
	}
	if err := RunSeeds(context.Background(), sc, []int64{1, 1}, 1, 3, func(SeedResult) error { return nil }); err == nil {
		t.Fatal("duplicate seed accepted")
	}
}

func TestSeedExecutionRetainsOfficialViolationKindsAndFullHeads(t *testing.T) {
	keys, err := TestValidators([]types.Address{{19: 1}, {19: 2}, {19: 3}, {19: 4}})
	if err != nil {
		t.Fatal(err)
	}
	sc := sim.Scenario{Validators: keys, Until: sim.Stop{Height: ^uint64(0), Duration: time.Minute}}
	result := &sim.Result{Heads: []uint64{9007199254740993, 2}, Violations: []sim.Violation{{Kind: "progress", Node: keys[0].Address(), Detail: "head below configured target"}, {Kind: "agreement", Node: keys[1].Address(), Detail: "conflicting block hashes"}}}
	got := seedExecution(sc, result)
	if got.StopHeight != ^uint64(0) || got.DurationNS != int64(time.Minute) || got.Nodes[0].Head != 9007199254740993 || got.Nodes[0].Address != keys[0].Address().Hex() || len(got.Violations) != 2 || got.Violations[0].Kind != "progress" || got.Violations[1].Kind != "agreement" || got.Violations[1].Detail != result.Violations[1].Detail {
		t.Fatal("official outcomes changed", got)
	}
	result.Heads[0] = 0
	result.Violations[0].Detail = "changed caller"
	if got.Nodes[0].Head != 9007199254740993 || got.Violations[0].Detail != "head below configured target" {
		t.Fatal("outcome aliases caller memory")
	}
}
