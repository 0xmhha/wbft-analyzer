package scenario

import (
	"github.com/0xmhha/wbft/conformance/sim"
	"testing"
	"time"
)

func TestMeasuredApplicationSamplesRemainPerNode(t *testing.T) {
	nodes, links := completeFixture()
	delay := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, delay, delay, sim.Stop{Height: 3, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	timing := AppTiming{}
	for i, n := range nodes {
		s := AppSample{Node: n.Address.Hex(), Input: n.Address.Hex(), Run: "r", FromLine: 1, ToLine: 2, Nanoseconds: int64(time.Duration(i+1) * time.Millisecond)}
		timing.Build = append(timing.Build, s)
		s.FromLine = 3
		s.ToLine = 3
		timing.Import = append(timing.Import, s)
	}
	fitted, err := ApplyAppTiming(sc, nodes, timing)
	if err != nil {
		t.Fatal(err)
	}
	if fitted.Nodes[2].BuildDelay[0] != 3*time.Millisecond || fitted.Nodes[3].ImportDelay[0] != 4*time.Millisecond || len(sc.Nodes[0].BuildDelay) != 0 {
		t.Fatal("per-node samples pooled or caller mutated")
	}
	timing.Build = timing.Build[:3]
	if _, err := ApplyAppTiming(sc, nodes, timing); err == nil {
		t.Fatal("missing node uses synthetic default")
	}
}
