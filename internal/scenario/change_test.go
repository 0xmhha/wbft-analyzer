package scenario

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
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
	changed, hash, err := ApplyNetworkChange(sc, NetworkChange{Kind: "cut_outgoing", Node: new(int), ToNS: int64(time.Minute)})
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
	if _, _, err := ApplyNetworkChange(sc, NetworkChange{Kind: "byzantine", Node: new(int), ToNS: 1}); err == nil {
		t.Fatal("unsupported change accepted")
	}
}

func indexPointer(n int) *int { return &n }
func edge(from, to int) DirectedEdge {
	return DirectedEdge{From: indexPointer(from), To: indexPointer(to)}
}

func TestNetworkChangeKeepsHistoricalCutCanonicalAndHash(t *testing.T) {
	change := NetworkChange{Kind: "cut_outgoing", Node: indexPointer(3), ToNS: 120000000000}
	raw, hash, err := change.Canonical()
	if err != nil || string(raw) != `{"kind":"cut_outgoing","node":3,"from_ns":0,"to_ns":120000000000}` || hash != "4cd121a9c521e43110f41328e653b5bba6d36d93dc12daebe0dbe90cc664435e" {
		t.Fatal(string(raw), hash, err)
	}
	var decoded NetworkChange
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	again, same, err := decoded.Canonical()
	if err != nil || !bytes.Equal(raw, again) || hash != same {
		t.Fatal("historical cut changed after storage", err)
	}
}

func TestDirectedPartitionPreservesDirectionAndSnapshotsCanonicalEdges(t *testing.T) {
	nodes, links := completeFixture()
	delay := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, delay, delay, sim.Stop{Height: 8, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	change := NetworkChange{Kind: "partition", FromNS: 10, ToNS: 20, Edges: []DirectedEdge{edge(3, 2), edge(3, 0), edge(1, 0)}}
	raw, hash, err := change.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	reordered := change
	reordered.Edges = []DirectedEdge{edge(1, 0), edge(3, 0), edge(3, 2)}
	other, same, err := reordered.Canonical()
	if err != nil || hash != same || !bytes.Equal(raw, other) {
		t.Fatal("edge order changed identity", err)
	}
	normalized, err := change.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	changed, _, err := ApplyNetworkChange(sc, change)
	if err != nil {
		t.Fatal(err)
	}
	p := changed.Partitions[0]
	if len(sc.Partitions) != 0 || p.From != 10 || p.To != 20 || len(p.Cut) != 0 || len(p.DirectedCut) != 3 {
		t.Fatal("partition changed baseline, interval, or reverse links", p)
	}
	want := [][2]int{{1, 0}, {3, 0}, {3, 2}}
	for i, pair := range want {
		if p.DirectedCut[i][0] != sc.Validators[pair[0]].Address() || p.DirectedCut[i][1] != sc.Validators[pair[1]].Address() {
			t.Fatal("recorded node direction changed", i)
		}
	}
	*change.Edges[0].From = 0
	if *normalized.Edges[2].From != 3 || p.DirectedCut[2][0] != sc.Validators[3].Address() {
		t.Fatal("caller mutation reached sealed partition")
	}
	// The existing outgoing intervention and an explicit equivalent edge set
	// must execute the same simulator partition without adding reverse edges.
	old, _, err := ApplyNetworkChange(sc, NetworkChange{Kind: "cut_outgoing", Node: indexPointer(3), ToNS: int64(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	explicit, _, err := ApplyNetworkChange(sc, NetworkChange{Kind: "partition", Edges: []DirectedEdge{edge(3, 2), edge(3, 0), edge(3, 1)}, ToNS: int64(time.Minute)})
	if err != nil || !reflect.DeepEqual(old.Partitions, explicit.Partitions) {
		t.Fatal("equivalent outgoing partition differs", err)
	}
}

func TestDirectedPartitionRejectsAmbiguousOrOutOfScopeRequests(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"partition","node":null,"from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}]}`,
		`{"kind":"partition","Node":null,"from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}]}`,
		`{"kind":"cut_outgoing","node":0,"from_ns":0,"to_ns":1,"edges":null}`,
		`{"kind":"cut_outgoing","from_ns":0,"to_ns":1}`,
		`{"kind":"partition","from_ns":null,"to_ns":1,"edges":[{"from":0,"to":1}]}`,
		`{"kind":"partition","from_ns":0,"to_ns":1,"edges":[]}`,
		`{"kind":"partition","from_ns":0,"to_ns":1,"edges":[{"to":1}]}`,
		`{"kind":"partition","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":0}]}`,
		`{"kind":"partition","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1},{"from":0,"to":1}]}`,
		`{"kind":"partition","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":256}]}`,
		`{"kind":"partition","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1,"transaction":true}]}`,
		`{"kind":"transaction","from_ns":0,"to_ns":1}`, `{"kind":"byzantine","from_ns":0,"to_ns":1}`,
	} {
		var change NetworkChange
		if json.Unmarshal([]byte(raw), &change) == nil {
			t.Fatal("ambiguous change accepted", raw)
		}
	}
	for _, change := range []NetworkChange{
		{Kind: "partition", ToNS: 1, Edges: []DirectedEdge{edge(4, 0)}},
		{Kind: "partition", ToNS: int64(time.Second) + 1, Edges: []DirectedEdge{edge(0, 1)}},
		{Kind: "partition", FromNS: -1, ToNS: 1, Edges: []DirectedEdge{edge(0, 1)}},
		{Kind: "partition", FromNS: 2, ToNS: 1, Edges: []DirectedEdge{edge(0, 1)}},
		{Kind: "partition", ToNS: int64(24*time.Hour) + 1, Edges: []DirectedEdge{edge(0, 1)}},
	} {
		if change.ValidateFor(4, time.Second) == nil {
			t.Fatal("out-of-scope change accepted", change)
		}
	}
}

func TestDirectedPartitionSupportsTheWholeBoundedNodeSet(t *testing.T) {
	edges := []DirectedEdge{}
	for from := range maxChangeNodes {
		for to := range maxChangeNodes {
			if from != to {
				edges = append(edges, edge(from, to))
			}
		}
	}
	change := NetworkChange{Kind: "partition", ToNS: 1, Edges: edges}
	raw, _, err := change.Canonical()
	if err != nil || len(raw) <= 4096 || len(raw) > MaxChangeRequestBytes || change.ValidateFor(maxChangeNodes, time.Second) != nil {
		t.Fatal("complete directed edge set not supported", len(raw), err)
	}
	var decoded NetworkChange
	if err := json.Unmarshal(raw, &decoded); err != nil || len(decoded.Edges) != maxChangeNodes*(maxChangeNodes-1) {
		t.Fatal("complete edge set did not survive storage", err)
	}
	extra := append(append([]DirectedEdge{}, edges...), edge(0, 1))
	change.Edges = extra
	if _, _, err := change.Canonical(); err == nil {
		t.Fatal("excess edge count accepted")
	}
	if strings.Contains(string(raw), `"node"`) {
		t.Fatal("partition retained an unrelated source node")
	}
}
