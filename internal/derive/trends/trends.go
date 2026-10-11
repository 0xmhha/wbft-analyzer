// Package trends derives observation rates from inspector reports and
// evaluates alert rules on them (design.md 6.7). The inspector reports how
// often an observation occurred but sets no threshold; the analyzer keeps
// the rates over reports and raises alerts the operator configures.
package trends

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sort"
)

// Observation is the part of a report observation a rate needs.
type Observation struct {
	Kind  string
	Node  string // empty for the whole run
	Count int64
}

// Point is the rate of one observation kind in one report: count divided
// by the number of heights of the report's range. Node is empty for the
// rate over all nodes.
type Point struct {
	Report string // report ID
	At     string // the report's finish time (RFC 3339), the order of points
	Kind   string
	Node   string
	Rate   float64
}

// ErrRange is a report range that gives no height count.
var ErrRange = errors.New("trends: the report range is not from <= to")

// Points returns the points of one report with the range [from, to]
// (decimal block numbers): one per kind over all nodes, and one per kind
// and node for the observations that name a node. Points are sorted by
// kind and node.
func Points(report, at, from, to string, obs []Observation) ([]Point, error) {
	f, ok1 := new(big.Int).SetString(from, 10)
	t, ok2 := new(big.Int).SetString(to, 10)
	if !ok1 || !ok2 || f.Cmp(t) > 0 {
		return nil, fmt.Errorf("%w: [%s, %s]", ErrRange, from, to)
	}
	heights, _ := new(big.Float).SetInt(new(big.Int).Add(new(big.Int).Sub(t, f), big.NewInt(1))).Float64()
	type key struct{ kind, node string }
	sums := map[key]int64{}
	for _, o := range obs {
		sums[key{o.Kind, ""}] += o.Count
		if o.Node != "" {
			sums[key{o.Kind, o.Node}] += o.Count
		}
	}
	out := make([]Point, 0, len(sums))
	for k, n := range sums { // sorted below
		out = append(out, Point{Report: report, At: at, Kind: k.kind, Node: k.node, Rate: float64(n) / heights})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Node < out[j].Node
	})
	return out, nil
}

// Mode is how a rule compares the recent rates.
type Mode string

// The modes of design.md 6.7, 2.
const (
	// Absolute fires when the median of the recent window is above the
	// threshold.
	Absolute Mode = "absolute"
	// Relative fires when the median of the recent window is above the
	// median of the baseline window (the points just before it) times the
	// threshold.
	Relative Mode = "relative"
)

// Rule is an alert rule of one network: kind and node select the points
// (node empty for the rate over all nodes). There are no default rules;
// the operator sets them per network.
type Rule struct {
	Kind      string
	Node      string
	Window    int // points of the recent window
	Baseline  int // points of the baseline window (Relative)
	Mode      Mode
	Threshold float64
}

// State is the state of a rule.
type State string

// The states of an alert.
const (
	// Pending: too few points to evaluate the rule.
	Pending  State = "pending"
	Firing   State = "firing"
	Resolved State = "resolved"
)

// Evaluation is the result of a rule on a series of points.
type Evaluation struct {
	State    State
	Recent   float64 // median of the recent window
	Baseline float64 // median of the baseline window (Relative)
}

// Check reports a rule that cannot be evaluated.
func (r Rule) Check() error {
	switch {
	case r.Kind == "":
		return errors.New("trends: a rule needs a kind")
	case r.Window < 1:
		return errors.New("trends: the window needs at least one point")
	case r.Mode == Relative && r.Baseline < 1:
		return errors.New("trends: a relative rule needs a baseline window")
	case r.Mode != Absolute && r.Mode != Relative:
		return fmt.Errorf("trends: unknown mode %q", r.Mode)
	case r.Threshold < 0:
		return errors.New("trends: the threshold is negative")
	}
	return nil
}

// Evaluate applies the rule to the points of its kind and node, ordered by
// At (then by report ID). Without enough points the state is Pending; a
// rule that does not hold is Resolved.
func (r Rule) Evaluate(points []Point) (Evaluation, error) {
	if err := r.Check(); err != nil {
		return Evaluation{}, err
	}
	var series []Point
	for _, p := range points {
		if p.Kind == r.Kind && p.Node == r.Node {
			series = append(series, p)
		}
	}
	sort.SliceStable(series, func(i, j int) bool {
		if series[i].At != series[j].At {
			return series[i].At < series[j].At
		}
		return series[i].Report < series[j].Report
	})
	need := r.Window
	if r.Mode == Relative {
		need += r.Baseline
	}
	if len(series) < need {
		return Evaluation{State: Pending}, nil
	}
	recent := median(series[len(series)-r.Window:])
	e := Evaluation{Recent: recent, State: Resolved}
	switch r.Mode {
	case Absolute:
		if recent > r.Threshold {
			e.State = Firing
		}
	case Relative:
		end := len(series) - r.Window
		e.Baseline = median(series[end-r.Baseline : end])
		if recent > e.Baseline*r.Threshold {
			e.State = Firing
		}
	}
	return e, nil
}

func median(ps []Point) float64 {
	v := make([]float64, len(ps))
	for i, p := range ps {
		v[i] = p.Rate
	}
	slices.Sort(v)
	n := len(v)
	if n%2 == 1 {
		return v[n/2]
	}
	return (v[n/2-1] + v[n/2]) / 2
}
