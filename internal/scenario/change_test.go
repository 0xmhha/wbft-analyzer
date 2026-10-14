package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
)

func TestOutgoingCutChangesRealDecisionRounds(t *testing.T) {
	nodes, links := completeFixture()
	delay := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, delay, delay, sim.Stop{Height: 8, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	changed, hash, err := ApplyCutOutgoing(sc, CutOutgoing{Kind: "cut_outgoing", Node: 0, ToNS: int64(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 64 || len(sc.Partitions) != 0 || len(changed.Partitions[0].DirectedCut) != 3 || len(changed.Partitions[0].Cut) != 0 {
		t.Fatal("cut changed reverse links or caller")
	}
	seeds := make([]int64, 32)
	for i := range seeds {
		seeds[i] = int64(i + 1)
	}
	collect := func(s sim.Scenario) int {
		late := 0
		err := RunSeeds(context.Background(), s, seeds, 1, 8, func(r SeedResult) error {
			if r.Status != "complete" {
				t.Fatalf("run %+v", r)
			}
			for _, h := range r.Heights {
				if h.Round > 0 {
					late++
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return late
	}
	baseline, cut := collect(sc), collect(changed)
	if baseline != 0 || cut == 0 {
		t.Fatalf("decision rounds baseline=%d cut=%d", baseline, cut)
	}
	if _, _, err := ApplyCutOutgoing(sc, CutOutgoing{Kind: "byzantine", Node: 0, ToNS: 1}); err == nil {
		t.Fatal("unsupported change accepted")
	}
}
