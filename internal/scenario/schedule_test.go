package scenario

import (
	"github.com/0xmhha/wbft/conformance/sim"
	"testing"
	"time"
)

func TestRuntimeScheduleBindsRecordedNodes(t *testing.T) {
	nodes, links := completeFixture()
	d := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, d, d, sim.Stop{Height: 3, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	runtimes := []Runtime{}
	for _, n := range nodes {
		runtimes = append(runtimes, Runtime{Node: n.Address.Hex(), Starts: 1, SignFloorState: "none"})
	}
	runtimes[0].Events = []RuntimeEvent{{Action: "stop", AtNS: int64(time.Second), Line: 2, Run: "r"}, {Action: "restart", AtNS: int64(2 * time.Second), Line: 3, Run: "r2"}}
	fitted, err := ApplyRuntime(sc, nodes, runtimes)
	if err != nil || len(fitted.Schedule) != 2 || fitted.Schedule[0].Node != sc.Validators[0].Address() || len(sc.Schedule) != 0 {
		t.Fatal("schedule binding", err)
	}
	runtimes[0].StartNS = int64(time.Second)
	delayed, err := ApplyRuntime(sc, nodes, runtimes)
	if err != nil || delayed.Nodes[0].StartAfter != time.Second || sc.Nodes[0].StartAfter != 0 {
		t.Fatal("delayed initial start not preserved", err)
	}
	runtimes[0].StartNS = 0
	runtimes[0].SignFloorState = "unavailable"
	if _, err := ApplyRuntime(sc, nodes, runtimes); err == nil {
		t.Fatal("unknown sign floor ignored")
	}
}
