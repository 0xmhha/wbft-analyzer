package scenario

import (
	"bytes"
	"encoding/json"
	"math/bits"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

const maxLinkDelay = 24 * time.Hour

// DelayScale is an exact nonnegative rational. Canonical form divides both
// terms by their GCD; conversion to integer nanoseconds rounds down.
type DelayScale struct {
	Numerator   uint64 `json:"numerator,string"`
	Denominator uint64 `json:"denominator,string"`
}

func (s *DelayScale) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Numerator   *uint64 `json:"numerator,string"`
		Denominator *uint64 `json:"denominator,string"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if wire.Numerator == nil || wire.Denominator == nil {
		return errNetworkChange
	}
	*s = DelayScale{Numerator: *wire.Numerator, Denominator: *wire.Denominator}
	return nil
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
func (c NetworkChange) IsLinkDelay() bool {
	return c.Kind == "set_link_delay" || c.Kind == "scale_link_delay"
}

func changedDelay(c NetworkChange, original time.Duration) (time.Duration, error) {
	if original < 0 {
		return 0, errNetworkChange
	}
	if c.Kind == "set_link_delay" {
		if c.DelayNS == nil {
			return 0, errNetworkChange
		}
		return time.Duration(*c.DelayNS), nil
	}
	if c.Scale == nil || c.Scale.Denominator == 0 {
		return 0, errNetworkChange
	}
	high, low := bits.Mul64(uint64(original), c.Scale.Numerator)
	if high >= c.Scale.Denominator {
		return 0, errNetworkChange
	}
	quotient, _ := bits.Div64(high, low, c.Scale.Denominator)
	if quotient > uint64(maxLinkDelay) {
		return 0, errNetworkChange
	}
	return time.Duration(quotient), nil
}

// LinkDelayBounds retains only immutable per-edge maxima, not simulator keys.
// A missing or ambiguous explicit link never falls back to synthetic defaults.
func LinkDelayBounds(sc sim.Scenario) (map[[2]int]time.Duration, error) {
	index := map[types.Address]int{}
	for i, v := range sc.Validators {
		if _, exists := index[v.Address()]; exists {
			return nil, errNetworkChange
		}
		index[v.Address()] = i
	}
	bounds := map[[2]int]time.Duration{}
	for _, link := range sc.Links {
		from, okA := index[link.From]
		to, okB := index[link.To]
		key := [2]int{from, to}
		if !okA || !okB || from == to || len(link.Delay) == 0 {
			return nil, errNetworkChange
		}
		if _, exists := bounds[key]; exists {
			return nil, errNetworkChange
		}
		var maximum time.Duration
		for _, d := range link.Delay {
			if d < 0 {
				return nil, errNetworkChange
			}
			if d > maximum {
				maximum = d
			}
		}
		bounds[key] = maximum
	}
	if len(bounds) != len(sc.Validators)*(len(sc.Validators)-1) {
		return nil, errNetworkChange
	}
	return bounds, nil
}

// ValidateDelayBounds rejects unrepresentable transformations before queuing.
// Execution validates again against freshly reconstructed source samples.
func (c NetworkChange) ValidateDelayBounds(bounds map[[2]int]time.Duration) error {
	normalized, err := c.Normalized()
	if err != nil {
		return err
	}
	if !normalized.IsLinkDelay() {
		return nil
	}
	for _, edge := range normalized.Edges {
		maximum, found := bounds[[2]int{*edge.From, *edge.To}]
		if !found {
			return errNetworkChange
		}
		if _, err := changedDelay(normalized, maximum); err != nil {
			return err
		}
	}
	return nil
}

func applyLinkDelay(sc sim.Scenario, c NetworkChange) (sim.Scenario, string, error) {
	bounds, err := LinkDelayBounds(sc)
	if err != nil {
		return sc, "", err
	}
	if err := c.ValidateDelayBounds(bounds); err != nil {
		return sc, "", err
	}
	selected := map[[2]types.Address]bool{}
	for _, edge := range c.Edges {
		selected[[2]types.Address{sc.Validators[*edge.From].Address(), sc.Validators[*edge.To].Address()}] = true
	}
	links := make([]sim.Link, len(sc.Links))
	for i, link := range sc.Links {
		links[i] = link
		links[i].Delay = append([]time.Duration(nil), link.Delay...)
		if !selected[[2]types.Address{link.From, link.To}] {
			continue
		}
		// Preserve sample cardinality so a constant intervention does not silently
		// change the simulator's random draw policy or the loss probability.
		for j, d := range link.Delay {
			value, err := changedDelay(c, d)
			if err != nil {
				return sc, "", err
			}
			links[i].Delay[j] = value
		}
	}
	sc.Links = links
	_, hash, err := c.Canonical()
	return sc, hash, err
}
