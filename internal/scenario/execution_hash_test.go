package scenario

import (
	"github.com/0xmhha/wbft/conformance/sim"
	"testing"
	"time"
)

func TestExecutionIdentityPinsOptionsWithoutExposingKeys(t *testing.T) {
	nodes, links := completeFixture()
	d := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, d, d, sim.Stop{Height: 3, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	first, err := ExecutionHash(sc)
	if err != nil {
		t.Fatal(err)
	}
	sc.Nodes[0].StartAfter = time.Second
	other, err := ExecutionHash(sc)
	if err != nil || first == other {
		t.Fatal("initial timing not pinned")
	}
	sc.Validators[0].ECDSA = append([]byte(nil), sc.Validators[1].ECDSA...)
	if _, err := ExecutionHash(sc); err == nil {
		t.Fatal("changed key kept old identity")
	}
}

func TestExecutionIdentityPinsWallClockPhase(t *testing.T) {
	nodes, links := completeFixture()
	d := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, d, d, sim.Stop{Height: 3, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defaultHash, err := ExecutionHash(sc)
	if err != nil {
		t.Fatal(err)
	}
	sc.WallOrigin = sim.Epoch
	explicitHash, err := ExecutionHash(sc)
	if err != nil || defaultHash != explicitHash {
		t.Fatal("same effective origin changed identity", err)
	}
	sc.WallOrigin = sc.WallOrigin.In(time.FixedZone("same instant", 3600))
	zoneHash, err := ExecutionHash(sc)
	if err != nil || zoneHash != explicitHash {
		t.Fatal("zone changed identity", err)
	}
	sc.WallOrigin = sc.WallOrigin.Add(time.Nanosecond)
	phaseHash, err := ExecutionHash(sc)
	if err != nil || phaseHash == explicitHash {
		t.Fatal("fractional phase omitted", err)
	}
	sc.WallOrigin = sc.WallOrigin.Add(time.Second)
	secondHash, err := ExecutionHash(sc)
	if err != nil || secondHash == phaseHash {
		t.Fatal("wall second omitted", err)
	}
}
