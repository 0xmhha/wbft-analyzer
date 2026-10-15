package scenario

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func intervalHeights(periods []uint64) []Height {
	out := make([]Height, len(periods))
	now := uint64(1700000000)
	for i, p := range periods {
		now += p
		out[i] = Height{Number: uint64(i + 1), Time: now, PeriodSeconds: p}
	}
	return out
}

func repeatIntervals(pattern []uint64, n int) []Height {
	periods := make([]uint64, n)
	for i := range periods {
		periods[i] = pattern[i%len(pattern)]
	}
	return intervalHeights(periods)
}

func intervalSeed(seed int64, heights []Height) SeedResult {
	return SeedResult{Seed: seed, Status: "complete", Heights: append([]Height(nil), heights...)}
}

func TestHeaderIntervalComparisonPreservesTheFullDistribution(t *testing.T) {
	recorded := repeatIntervals([]uint64{1, 3}, 64)
	simulated := repeatIntervals([]uint64{1, 7}, 64)
	runs := []SeedResult{intervalSeed(2, simulated), intervalSeed(1, simulated)}
	before := append([]SeedResult(nil), runs...)
	got, err := CompareHeaderIntervals([][]Height{recorded}, runs, 1)
	if err != nil || got.Status != "distinguishable" || got.Comparison == nil || got.Comparison.P == nil || got.Comparison.Upper >= baselineAlpha {
		t.Fatalf("complete tail categories were lost: %+v %v", got, err)
	}
	if got.MaximumCDFDifference != .5 || len(got.Recorded[0].Counts) != 3 || got.Recorded[0].Counts[1].Seconds != 3 || got.Simulated[0].Counts[2].Seconds != 7 {
		t.Fatal("intervals collapsed to a late/not-late threshold", got)
	}
	if !reflect.DeepEqual(runs, before) || got.Simulated[0].Seed != "1" {
		t.Fatal("seed order changed or was not canonicalized")
	}
	runs[0], runs[1] = runs[1], runs[0]
	again, err := CompareHeaderIntervals([][]Height{recorded}, runs, 1)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("seed permutation changed evidence", err)
	}
}

func TestHeaderIntervalComparisonKeepsSingleRecordedRunGate(t *testing.T) {
	a, b := repeatIntervals([]uint64{1}, 64), repeatIntervals([]uint64{3}, 64)
	runs := []SeedResult{intervalSeed(1, a), intervalSeed(2, b)}
	got, err := CompareHeaderIntervals([][]Height{repeatIntervals([]uint64{1, 3}, 64)}, runs, 1)
	if err != nil || got.Status != "insufficient_recorded_runs" || got.Comparison != nil || got.SimulatedHomogeneity == nil || got.SimulatedHomogeneity.Upper >= baselineAlpha {
		t.Fatalf("heterogeneous runs were pooled: %+v %v", got, err)
	}
	multiple, err := CompareHeaderIntervals([][]Height{a, b}, runs, 1)
	if err != nil || multiple.Status != "not_distinguishable" || multiple.Comparison == nil || !strings.HasPrefix(multiple.Comparison.Method, "whole_run_cdf/") || multiple.MaximumCDFDifference != 0 {
		t.Fatalf("run permutation did not preserve heterogeneous runs: %+v %v", multiple, err)
	}
}

func TestHeaderIntervalProbabilityBoundsControlDecisions(t *testing.T) {
	p := .02
	for _, test := range []struct {
		probability ConditionalProbability
		status      string
	}{
		{ConditionalProbability{P: &p, Lower: .009, Upper: .03}, "precision_limited"},
		{ConditionalProbability{P: &p, Lower: .01, Upper: .03}, "not_distinguishable"},
		{ConditionalProbability{P: &p, Lower: 0, Upper: .009}, "distinguishable"},
		{ConditionalProbability{P: &p, Lower: 0, Upper: 1, Issue: "work_limit"}, "unavailable"},
		{ConditionalProbability{}, "unavailable"},
	} {
		if got := probabilityDecision(test.probability); got != test.status {
			t.Fatal("point estimate overrode its numerical bound", got, test.status)
		}
	}
}

func TestHeaderIntervalInputAndResourceLimitsStayUnproved(t *testing.T) {
	h := repeatIntervals([]uint64{1}, 8)
	valid := []SeedResult{intervalSeed(1, h), intervalSeed(2, h)}
	for _, change := range []func([]SeedResult){
		func(rs []SeedResult) { rs[1].Seed = rs[0].Seed },
		func(rs []SeedResult) { rs[1].Status = "partial" },
		func(rs []SeedResult) { rs[1].Violations = 1 },
		func(rs []SeedResult) { rs[1].Heights = rs[1].Heights[:7] },
		func(rs []SeedResult) { rs[1].Heights[3].Number++ },
		func(rs []SeedResult) { rs[1].Heights[3].PeriodSeconds++ },
		func(rs []SeedResult) { rs[1].Heights[3].Time-- },
	} {
		rs := []SeedResult{intervalSeed(1, h), intervalSeed(2, h)}
		change(rs)
		if _, err := CompareHeaderIntervals([][]Height{h}, rs, 1); err == nil {
			t.Fatal("invalid interval run accepted")
		}
	}
	if _, err := CompareHeaderIntervals(nil, valid, 1); err == nil {
		t.Fatal("missing recorded intervals accepted")
	}
	periods := make([]uint64, 2050)
	for i := range periods {
		periods[i] = uint64(i + 1)
	}
	large := intervalHeights(periods)
	got, err := CompareHeaderIntervals([][]Height{large}, []SeedResult{intervalSeed(1, large), intervalSeed(2, large)}, 1)
	if err != nil || got.Status != "resource_limit" || got.Comparison != nil || len(got.Recorded) != 0 {
		t.Fatal("unsupported categories were truncated or treated as evidence", got, err)
	}
	large[len(large)-1].Number++
	if _, err := CompareHeaderIntervals([][]Height{large}, []SeedResult{intervalSeed(1, large), intervalSeed(2, large)}, 1); err == nil {
		t.Fatal("resource limit hid a malformed suffix")
	}
}

func TestHeaderIntervalsKeepFullUnsignedIntegerCategories(t *testing.T) {
	a := []Height{{Number: 1, Time: math.MaxUint64, PeriodSeconds: math.MaxUint64}}
	b := []Height{{Number: 1, Time: math.MaxUint64 - 1, PeriodSeconds: math.MaxUint64 - 1}}
	got, err := CompareHeaderIntervals([][]Height{a}, []SeedResult{intervalSeed(1, b), intervalSeed(2, b)}, 1)
	if err != nil || len(got.Recorded[0].Counts) != 2 {
		t.Fatal(got, err)
	}
	raw, err := json.Marshal(got)
	if err != nil || !strings.Contains(string(raw), `"seconds":"18446744073709551615"`) || !strings.Contains(string(raw), `"seconds":"18446744073709551614"`) {
		t.Fatal("interval integers were rounded", string(raw), err)
	}
}
