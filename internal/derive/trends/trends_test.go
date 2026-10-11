package trends

import (
	"errors"
	"fmt"
	"math"
	"testing"
)

// TestPoints: one point per kind over all nodes, one per kind and node;
// the rate is the count over the heights of the range.
func TestPoints(t *testing.T) {
	ps, err := Points("r1", "2026-10-12T00:00:00Z", "101", "200", []Observation{
		{Kind: "late_seal", Node: "0xaa", Count: 3}, {Kind: "late_seal", Node: "0xbb", Count: 2}, {Kind: "stale_retry", Count: 10}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"late_seal  0.05", "late_seal 0xaa 0.03", "late_seal 0xbb 0.02", "stale_retry  0.1"}
	if len(ps) != len(want) {
		t.Fatalf("points %+v", ps)
	}
	for i, p := range ps {
		if got := fmt.Sprintf("%s %s %g", p.Kind, p.Node, p.Rate); got != want[i] {
			t.Errorf("point %d: %s, want %s", i, got, want[i])
		}
	}
	// Block numbers beyond 2^64 count heights exactly.
	ps, err = Points("r2", "t", "18446744073709551616", "18446744073709551625", []Observation{{Kind: "k", Count: 5}})
	if err != nil || len(ps) != 1 || math.Abs(ps[0].Rate-0.5) > 1e-12 {
		t.Fatalf("big range: %+v %v", ps, err)
	}
	for _, r := range [][2]string{{"9", "8"}, {"x", "9"}, {"1", ""}} {
		if _, err := Points("r", "t", r[0], r[1], nil); !errors.Is(err, ErrRange) {
			t.Errorf("range %v: %v", r, err)
		}
	}
}

// series is ten reports of 100 heights each with the given counts of kind
// k, in time order.
func series(counts ...int64) []Point {
	var out []Point
	for i, c := range counts {
		ps, _ := Points(fmt.Sprintf("r%02d", i), fmt.Sprintf("2026-10-12T00:%02d:00Z", i), "1", "100", []Observation{{Kind: "k", Count: c}})
		out = append(out, ps...)
	}
	return out
}

// TestRelative: ten synthetic reports with a rising count fire the
// relative rule; when the count falls back the rule resolves (A0 exit
// criterion).
func TestRelative(t *testing.T) {
	r := Rule{Kind: "k", Window: 3, Baseline: 5, Mode: Relative, Threshold: 2}
	steady := []int64{2, 2, 3, 2, 2}
	cases := []struct {
		name   string
		counts []int64
		want   State
	}{
		{"rising", append(append([]int64{}, steady...), 3, 5, 8, 9, 10), Firing},
		{"falls back", append(append([]int64{}, steady...), 3, 5, 8, 9, 10, 3, 2, 2), Resolved},
		{"steady", append(append([]int64{}, steady...), 2, 3, 2, 2, 3), Resolved},
		// Above the baseline but below twice it: not an alert.
		{"mild rise", append(append([]int64{}, steady...), 2, 3, 3, 3, 3), Resolved},
		{"too few", []int64{2, 2, 9}, Pending},
	}
	for _, c := range cases {
		e, err := r.Evaluate(series(c.counts...))
		if err != nil || e.State != c.want {
			t.Errorf("%s: %+v %v, want %s", c.name, e, err, c.want)
		}
	}
	// The firing evaluation reports the two medians.
	e, _ := r.Evaluate(series(2, 2, 3, 2, 2, 3, 5, 8, 9, 10))
	if e.Recent != 0.09 || e.Baseline != 0.03 {
		t.Fatalf("medians %+v", e)
	}
}

// TestAbsolute fires on the median of the recent window and only on the
// rule's kind and node.
func TestAbsolute(t *testing.T) {
	r := Rule{Kind: "k", Window: 2, Mode: Absolute, Threshold: 0.05}
	if e, _ := r.Evaluate(series(1, 1, 6, 7)); e.State != Firing {
		t.Fatalf("above: %+v", e)
	}
	if e, _ := r.Evaluate(series(9, 9, 1, 2)); e.State != Resolved {
		t.Fatalf("below: %+v", e)
	}
	r.Node = "0xaa"
	if e, _ := r.Evaluate(series(9, 9, 9)); e.State != Pending {
		t.Fatalf("other node: %+v", e)
	}
}

// TestRuleCheck refuses rules that cannot be evaluated.
func TestRuleCheck(t *testing.T) {
	for _, r := range []Rule{
		{Window: 1, Mode: Absolute},
		{Kind: "k", Mode: Absolute},
		{Kind: "k", Window: 1, Mode: Relative},
		{Kind: "k", Window: 1, Mode: "median"},
		{Kind: "k", Window: 1, Mode: Absolute, Threshold: -1},
	} {
		if _, err := r.Evaluate(nil); err == nil {
			t.Errorf("rule %+v accepted", r)
		}
	}
}
