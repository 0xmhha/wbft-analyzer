package scenario

import (
	"encoding/json"
	"math"
	"math/big"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
)

func delayPointer(n int64) *int64 { return &n }
func delayFixture(t *testing.T) sim.Scenario {
	t.Helper()
	nodes, links := completeFixture()
	samples := []time.Duration{1, 3, 5}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, samples, samples, sim.Stop{Height: 8, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for i := range sc.Links {
		sc.Links[i].Delay = append([]time.Duration{}, samples...)
		sc.Links[i].Loss = .125
	}
	return sc
}
func TestDirectedDelayTransformsOnlySelectedSamplesAndPreservesBaseline(t *testing.T) {
	sc := delayFixture(t)
	before, err := ExecutionHash(sc)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []NetworkChange{
		{Kind: "set_link_delay", ToNS: int64(time.Minute), Edges: []DirectedEdge{edge(0, 1)}, DelayNS: delayPointer(250000000)},
		{Kind: "scale_link_delay", ToNS: int64(time.Minute), Edges: []DirectedEdge{edge(0, 1)}, Scale: &DelayScale{Numerator: 3, Denominator: 2}},
	} {
		changed, _, err := ApplyNetworkChange(sc, change)
		if err != nil {
			t.Fatal(err)
		}
		for i, link := range changed.Links {
			wanted := []time.Duration{1, 3, 5}
			if link.From == sc.Validators[0].Address() && link.To == sc.Validators[1].Address() {
				if change.Kind == "set_link_delay" {
					wanted = []time.Duration{250000000, 250000000, 250000000}
				} else {
					wanted = []time.Duration{1, 4, 7}
				}
			}
			if !reflect.DeepEqual(link.Delay, wanted) || link.Loss != sc.Links[i].Loss {
				t.Fatal("direction, samples, cardinality, or loss changed", link, wanted)
			}
		}
		after, _ := ExecutionHash(sc)
		if before != after {
			t.Fatal("caller baseline mutated")
		}
		changed.Links[0].Delay[0] = 99
		if sc.Links[0].Delay[0] != 1 {
			t.Fatal("changed samples alias baseline")
		}
	}
}
func TestDelayScaleCanonicalIdentityAndZeroCostKeepTheDeclaredPolicy(t *testing.T) {
	c := NetworkChange{Kind: "scale_link_delay", ToNS: int64(time.Minute), Edges: []DirectedEdge{edge(0, 1)}, Scale: &DelayScale{Numerator: 2, Denominator: 2}}
	raw, hash, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	c.Scale = &DelayScale{Numerator: 1, Denominator: 1}
	other, same, err := c.Canonical()
	if err != nil || string(raw) != string(other) || hash != same {
		t.Fatal("equivalent rational changed identity", err)
	}
	sc := delayFixture(t)
	changed, _, err := ApplyNetworkChange(sc, c)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := ExecutionHash(sc)
	after, _ := ExecutionHash(changed)
	if before != after {
		t.Fatal("identity scale changed execution")
	}
	c.Scale = &DelayScale{Numerator: 0, Denominator: math.MaxUint64}
	normalized, err := c.Normalized()
	if err != nil || normalized.Scale.Numerator != 0 || normalized.Scale.Denominator != 1 {
		t.Fatal(normalized, err)
	}
	changed, _, err = ApplyNetworkChange(sc, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range changed.Links {
		if link.From == sc.Validators[0].Address() && link.To == sc.Validators[1].Address() && !reflect.DeepEqual(link.Delay, []time.Duration{0, 0, 0}) {
			t.Fatal("zero scale changed sample cardinality")
		}
	}
}
func TestDelayArithmeticMatchesIndependentBigIntegerFloorWithoutOverflow(t *testing.T) {
	r := rand.New(rand.NewPCG(17, 31))
	cases := [][3]uint64{{1, 3, 2}, {math.MaxInt64, math.MaxUint64, 1}, {math.MaxInt64, 1, math.MaxUint64}, {0, math.MaxUint64, 1}, {uint64(24 * time.Hour), 1, 1}, {uint64(24*time.Hour) + 1, 1, 1}}
	for range 256 {
		cases = append(cases, [3]uint64{r.Uint64() >> 1, r.Uint64(), r.Uint64() | 1})
	}
	for _, x := range cases {
		value := new(big.Int).Mul(new(big.Int).SetUint64(x[0]), new(big.Int).SetUint64(x[1]))
		value.Div(value, new(big.Int).SetUint64(x[2]))
		got, err := changedDelay(NetworkChange{Kind: "scale_link_delay", Scale: &DelayScale{Numerator: x[1], Denominator: x[2]}}, time.Duration(x[0]))
		if value.Cmp(big.NewInt(int64(maxLinkDelay))) > 0 {
			if err == nil {
				t.Fatal("overflow or unbounded delay accepted", x, got)
			}
			continue
		}
		if err != nil || int64(got) != value.Int64() {
			t.Fatal("delay differs from exact integer floor", x, got, value, err)
		}
	}
}
func TestLinkDelayRejectsMissingSamplesInvalidFactorsAndPartialRunWindows(t *testing.T) {
	sc := delayFixture(t)
	valid := NetworkChange{Kind: "scale_link_delay", ToNS: int64(time.Minute), Edges: []DirectedEdge{edge(0, 1)}, Scale: &DelayScale{Numerator: 2, Denominator: 1}}
	for _, raw := range []string{
		`{"kind":"set_link_delay","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}]}`,
		`{"kind":"set_link_delay","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}],"delay_ns":-1}`,
		`{"kind":"scale_link_delay","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}],"scale":{"numerator":"2","denominator":"0"}}`,
		`{"kind":"scale_link_delay","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}],"scale":{"numerator":2,"denominator":"1"}}`,
		`{"kind":"scale_link_delay","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}],"scale":{"denominator":"1"}}`,
		`{"kind":"scale_link_delay","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}],"scale":{"numerator":null,"denominator":"1"}}`,
		`{"kind":"scale_link_delay","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}],"scale":{"numerator":"2","denominator":"1","extra":1}}`,
		`{"kind":"partition","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}],"scale":null}`,
		`{"kind":"cut_outgoing","from_ns":0,"to_ns":1,"node":0,"delay_ns":null}`,
	} {
		var c NetworkChange
		if json.Unmarshal([]byte(raw), &c) == nil {
			t.Fatal("invalid or unrelated delay field accepted", raw)
		}
	}
	for _, kind := range []string{"scale_link_delay", "set_link_delay"} {
		c := valid
		c.Kind = kind
		if kind == "set_link_delay" {
			c.Scale = nil
			c.DelayNS = delayPointer(1)
		}
		c.FromNS = 1
		if c.ValidateFor(4, time.Minute) == nil {
			t.Fatal("partial window silently became full-run delay")
		}
		c.FromNS = 0
		c.ToNS--
		if c.ValidateFor(4, time.Minute) == nil {
			t.Fatal("truncated window accepted")
		}
	}
	c := valid
	c.Scale = &DelayScale{Numerator: math.MaxUint64, Denominator: 1}
	bounds, err := LinkDelayBounds(sc)
	if err != nil {
		t.Fatal(err)
	}
	if c.ValidateDelayBounds(bounds) == nil {
		t.Fatal("source-dependent delay overflow accepted")
	}
	sc.Links = sc.Links[1:]
	if _, _, err := ApplyNetworkChange(sc, valid); err == nil {
		t.Fatal("missing explicit link used synthetic fallback")
	}
}
