package scenario

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

func TestSeedExecutionRetainsPartialLightChecks(t *testing.T) {
	source := &sim.Result{LightChecks: []sim.LightCheck{{Node: types.Address{1}, Number: "18446744073709551616", Hash: types.Hash{2}, Verdict: "CANNOT_DECIDE", Reason: "application state required", FullStateVerified: true}}}
	got := seedExecution(sim.Scenario{}, source)
	if len(got.LightChecks) != 1 || got.LightChecks[0].Number != "18446744073709551616" || got.LightChecks[0].Hash != source.LightChecks[0].Hash.Hex() || got.LightChecks[0].Node != source.LightChecks[0].Node.Hex() || got.LightChecks[0].Verdict != "CANNOT_DECIDE" || !got.LightChecks[0].CandidateStateVerified {
		t.Fatal(got.LightChecks)
	}
	source.LightChecks[0].Reason = "changed"
	source.LightChecks[0].Number = "0"
	if got.LightChecks[0].Reason != "application state required" || got.LightChecks[0].Number != "18446744073709551616" {
		t.Fatal("observation aliases caller")
	}
	raw, err := json.Marshal(seedExecution(sim.Scenario{}, &sim.Result{}))
	if err != nil || strings.Contains(string(raw), "light_checks") {
		t.Fatal("default historical JSON changed", string(raw), err)
	}
}

func TestActivatedEpochSeedKeepsPartialLightVerdicts(t *testing.T) {
	sc := timingFixture(t)
	sc.Params.EpochLength = 2
	sc.Params.RuleActivations = map[types.RuleName]string{types.EpochInfoInProposal: "2", types.CommittedEpochDiligence: "2"}
	count := 0
	err := RunSeeds(context.Background(), sc, []int64{1}, 1, 7, func(r SeedResult) error {
		count++
		if r.Status != "complete" || r.Violations != 0 || r.Execution == nil || len(r.Execution.LightChecks) == 0 {
			t.Fatal("normal activated epoch did not retain partial observations", r)
		}
		for _, check := range r.Execution.LightChecks {
			if check.Verdict != "CANNOT_DECIDE" || !check.CandidateStateVerified {
				t.Fatal(check)
			}
		}
		return nil
	})
	if err != nil || count != 1 {
		t.Fatal(err, count)
	}
}
