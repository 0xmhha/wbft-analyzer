package scenario

import (
	"context"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

func TestNormalBLSRevealScenarioUsesActualConfiguredJournals(t *testing.T) {
	sc := timingFixture(t)
	sc.Params.EpochLength = 4
	sc.Params.RuleActivations = map[types.RuleName]string{types.RejectNumberJump: "0", types.BLSRandao: "3"}
	directory := t.TempDir()
	result, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: directory})
	if err != nil || len(result.Violations) != 0 {
		t.Fatal(result.Violations, err)
	}
	if len(result.Chain) < 9 {
		t.Fatal("normal configured chain did not reach target")
	}
	for n := 1; n <= 8; n++ {
		x, err := codec.DecodeExtra(result.Chain[n].Header)
		want := 65
		if n >= 3 {
			want = 96
		}
		if err != nil || len(x.RandaoReveal) != want {
			t.Fatal("actual configured reveal", n, err)
		}
	}
	for _, v := range sc.Validators {
		cfg := recordedTestConfiguration(t, directory, v)
		if at, ok := cfg.RuleActivation(types.BLSRandao); !ok || at.String() != "3" {
			t.Fatal("actual journal lost activation")
		}
		facts, err := InspectChain(result.Chain, cfg, 1, 7)
		if err != nil || facts.StaticConfiguration == nil || facts.StaticConfiguration.RuleActivations[string(types.BLSRandao)] != "3" {
			t.Fatal("recorded configuration not available to analysis", err)
		}
	}
}
