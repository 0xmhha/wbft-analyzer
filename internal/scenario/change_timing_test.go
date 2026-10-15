package scenario

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
)

func timingNumber(v uint64) *uint64 { return &v }

func timingFixture(t *testing.T) sim.Scenario {
	t.Helper()
	nodes, links := completeFixture()
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100, MaxRequestTimeoutSeconds: timingNumber(3)}, []time.Duration{time.Millisecond}, []time.Duration{time.Millisecond}, sim.Stop{Height: 8, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestTimingChangeOverlaysAllAndIndividualNodesWithoutMutatingSource(t *testing.T) {
	sc := timingFixture(t)
	sc.Nodes[1].Timing = &sim.TimingParams{RequestTimeoutSeconds: timingNumber(9), BlockPeriodSeconds: timingNumber(3)}
	before, err := ExecutionHash(sc)
	if err != nil {
		t.Fatal(err)
	}
	change := NetworkChange{Kind: "set_timing", ToNS: int64(time.Minute), Timing: &TimingChange{
		Global: &TimingValues{RequestTimeoutSeconds: timingNumber(5), MaxRequestTimeoutSeconds: timingNumber(0)},
		Nodes: []NodeTimingChange{
			{Node: indexPointer(3), Values: TimingValues{BlockPeriodSeconds: timingNumber(2)}},
			{Node: indexPointer(1), Values: TimingValues{RequestTimeoutSeconds: timingNumber(7)}},
		},
	}}
	changed, hash, err := ApplyNetworkChange(sc, change)
	if err != nil || len(hash) != 64 {
		t.Fatal(hash, err)
	}
	for i, n := range changed.Nodes {
		got, err := sim.ResolveTiming(changed.Params, n.Timing, changed.Until.Duration)
		wantTimeout, wantPeriod := uint64(5), uint64(1)
		if i == 1 {
			wantTimeout, wantPeriod = 7, 3
		}
		if i == 3 {
			wantPeriod = 2
		}
		if err != nil || got.RequestTimeoutSeconds != wantTimeout || got.BlockPeriodSeconds != wantPeriod || got.MaxRequestTimeoutSeconds == nil || *got.MaxRequestTimeoutSeconds != 0 || got.EpochLength != 100 {
			t.Fatal("wrong global/per-node precedence or inherited values", i, got, err)
		}
	}
	*change.Timing.Global.RequestTimeoutSeconds = 99
	*change.Timing.Nodes[1].Values.RequestTimeoutSeconds = 99
	if *changed.Nodes[1].Timing.RequestTimeoutSeconds != 7 {
		t.Fatal("execution aliases request values")
	}
	*changed.Nodes[1].Timing.BlockPeriodSeconds = 100
	after, err := ExecutionHash(sc)
	if err != nil || before != after || *sc.Nodes[1].Timing.BlockPeriodSeconds != 3 || *sc.Params.MaxRequestTimeoutSeconds != 3 {
		t.Fatal("baseline source mutated", err)
	}
	if !reflect.DeepEqual(changed.Links, sc.Links) || !reflect.DeepEqual(changed.Schedule, sc.Schedule) || !reflect.DeepEqual(changed.Validators, sc.Validators) || !reflect.DeepEqual(changed.App, sc.App) {
		t.Fatal("non-timing scenario options changed")
	}
}

func TestTimingChangeCanonicalOrderAndStrictStringValues(t *testing.T) {
	raw := `{"kind":"set_timing","from_ns":0,"to_ns":60000000000,"timing":{"global":{"max_request_timeout_seconds":"0"},"nodes":[{"node":3,"values":{"block_period_seconds":"2"}},{"node":1,"values":{"request_timeout_seconds":"7"}}]}}`
	var change NetworkChange
	if err := json.Unmarshal([]byte(raw), &change); err != nil {
		t.Fatal(err)
	}
	canonical, hash, err := change.Canonical()
	if err != nil || *change.Timing.Nodes[0].Node != 1 {
		t.Fatal(string(canonical), err)
	}
	var again NetworkChange
	if err := json.Unmarshal(canonical, &again); err != nil {
		t.Fatal(err)
	}
	roundtrip, same, err := again.Canonical()
	if err != nil || hash != same || string(canonical) != string(roundtrip) {
		t.Fatal("timing canonical form drifted", err)
	}
	invalidValues := []string{`{}`, `null`, `{"request_timeout_seconds":2}`, `{"request_timeout_seconds":"0"}`, `{"block_period_seconds":"0"}`, `{"max_request_timeout_seconds":"18446744073709551615"}`, `{"request_timeout_seconds":null}`, `{"Request_Timeout_Seconds":"2"}`, `{"request_timeout_seconds":"2","unknown":"3"}`, `{"block_period_seconds":"-1"}`, `{"block_period_seconds":"1.5"}`}
	for _, values := range invalidValues {
		body := `{"kind":"set_timing","from_ns":0,"to_ns":60000000000,"timing":{"global":` + values + `}}`
		if err := json.Unmarshal([]byte(body), &again); err == nil {
			t.Fatal("invalid explicit values accepted", body)
		}
	}
	for _, timing := range []string{`null`, `{}`, `{"nodes":null}`, `{"nodes":[]}`, `{"global":{"block_period_seconds":"2"},"nodes":[]}`, `{"global":null}`, `{"nodes":[{"node":1}]}`, `{"nodes":[{"node":null,"values":{"block_period_seconds":"2"}}]}`, `{"nodes":[{"node":1,"values":{"block_period_seconds":"2"},"extra":1}]}`, `{"nodes":[{"Node":1,"values":{"block_period_seconds":"2"}}]}`, `{"global":{"block_period_seconds":"2"},"unknown":[]}`} {
		body := `{"kind":"set_timing","from_ns":0,"to_ns":60000000000,"timing":` + timing + `}`
		if err := json.Unmarshal([]byte(body), &again); err == nil {
			t.Fatal("invalid timing structure accepted", body)
		}
	}
}

func TestTimingChangeBoundsAndScope(t *testing.T) {
	sc := timingFixture(t)
	valid := NetworkChange{Kind: "set_timing", ToNS: int64(time.Minute), Timing: &TimingChange{Global: &TimingValues{MaxRequestTimeoutSeconds: timingNumber(0)}}}
	if _, _, err := ApplyNetworkChange(sc, valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*NetworkChange){
		func(c *NetworkChange) { c.FromNS = 1 },
		func(c *NetworkChange) { c.ToNS-- },
		func(c *NetworkChange) {
			c.Timing = &TimingChange{Global: &TimingValues{RequestTimeoutSeconds: timingNumber(math.MaxUint64)}}
		},
		func(c *NetworkChange) {
			c.Timing = &TimingChange{Nodes: []NodeTimingChange{{Node: indexPointer(4), Values: TimingValues{BlockPeriodSeconds: timingNumber(2)}}}}
		},
		func(c *NetworkChange) {
			c.Timing = &TimingChange{Nodes: []NodeTimingChange{{Node: indexPointer(1), Values: TimingValues{BlockPeriodSeconds: timingNumber(2)}}, {Node: indexPointer(1), Values: TimingValues{RequestTimeoutSeconds: timingNumber(2)}}}}
		},
		func(c *NetworkChange) { c.Node = indexPointer(1) },
		func(c *NetworkChange) { c.Edges = []DirectedEdge{edge(0, 1)} },
		func(c *NetworkChange) { c.Kind = "partition"; c.Edges = []DirectedEdge{edge(0, 1)} },
	} {
		invalid := valid
		mutate(&invalid)
		if _, _, err := ApplyNetworkChange(sc, invalid); err == nil {
			t.Fatal("out-of-scope timing change accepted", invalid)
		}
	}
}

func TestTimingChangeIdentityAndPeriodAffectActualSimulation(t *testing.T) {
	sc := timingFixture(t)
	before, err := ExecutionHash(sc)
	if err != nil {
		t.Fatal(err)
	}
	want, err := sim.Run(context.Background(), sc, sim.Output{})
	if err != nil || len(want.Violations) != 0 {
		t.Fatal(err, want.Violations)
	}
	identity := NetworkChange{Kind: "set_timing", ToNS: int64(time.Minute), Timing: &TimingChange{Global: &TimingValues{RequestTimeoutSeconds: timingNumber(2)}}}
	changed, _, err := ApplyNetworkChange(sc, identity)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sim.Run(context.Background(), changed, sim.Output{})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("identity changed execution events, headers or journals", err)
	}
	identity.Timing.Global = &TimingValues{BlockPeriodSeconds: timingNumber(4)}
	changed, _, err = ApplyNetworkChange(sc, identity)
	if err != nil {
		t.Fatal(err)
	}
	got, err = sim.Run(context.Background(), changed, sim.Output{})
	if err != nil || len(got.Violations) != 0 {
		t.Fatal(err, got.Violations)
	}
	for i := 1; i < len(got.Chain); i++ {
		if got.Chain[i].Header.Time-got.Chain[i-1].Header.Time < 4 {
			t.Fatal("requested period was not applied to the fake application")
		}
	}
	after, err := ExecutionHash(sc)
	if err != nil || before != after {
		t.Fatal("baseline execution identity changed", err)
	}
	perNode := sc
	perNode.Nodes = append([]sim.NodeSpec(nil), sc.Nodes...)
	perNode.Nodes[1].Timing = &sim.TimingParams{MaxRequestTimeoutSeconds: timingNumber(0)}
	hash, err := ExecutionHash(perNode)
	if err != nil || hash == before {
		t.Fatal("per-node timing missing from executable identity", err)
	}
}
