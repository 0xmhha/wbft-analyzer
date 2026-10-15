package scenario

import (
	"errors"
	"sort"
	"strconv"
)

const HeaderTimeBaselineMethod = "wbft-header-interval-baseline/1"
const baselineAlpha = 0.01

type IntervalCount struct {
	Seconds uint64 `json:"seconds,string"`
	Count   int64  `json:"count"`
}

type IntervalHistogram struct {
	Run     string          `json:"run"`
	Seed    string          `json:"seed,omitempty"`
	Samples int             `json:"samples"`
	Counts  []IntervalCount `json:"counts"`
}

// HeaderTimeComparison retains every observed interval category. Statistical
// non-rejection is conditional on this model and its sampling assumptions.
type HeaderTimeComparison struct {
	Method                    string                  `json:"method"`
	Status                    string                  `json:"status"`
	Issue                     string                  `json:"issue,omitempty"`
	Alpha                     float64                 `json:"alpha"`
	From                      uint64                  `json:"from,string"`
	To                        uint64                  `json:"to,string"`
	RecordedRuns              int                     `json:"recorded_runs"`
	SimulatedRuns             int                     `json:"simulated_runs"`
	Recorded                  []IntervalHistogram     `json:"recorded"`
	Simulated                 []IntervalHistogram     `json:"simulated"`
	RecordedHomogeneity       *ConditionalProbability `json:"recorded_homogeneity"`
	SimulatedHomogeneity      *ConditionalProbability `json:"simulated_homogeneity"`
	Comparison                *ConditionalProbability `json:"comparison"`
	MaximumCDFDifference      float64                 `json:"maximum_cdf_difference"`
	NumericalErrorProbability float64                 `json:"numerical_error_probability"`
	Assumptions               []string                `json:"assumptions"`
}

func probabilityDecision(p ConditionalProbability) string {
	if p.P == nil || p.Issue != "" {
		return "unavailable"
	}
	if p.Upper < baselineAlpha {
		return "distinguishable"
	}
	if p.Lower >= baselineAlpha {
		return "not_distinguishable"
	}
	return "precision_limited"
}

func newHeaderTimeComparison(recorded, simulated int) HeaderTimeComparison {
	return HeaderTimeComparison{Method: HeaderTimeBaselineMethod, Status: "unavailable", Alpha: baselineAlpha, RecordedRuns: recorded, SimulatedRuns: simulated, Recorded: []IntervalHistogram{}, Simulated: []IntervalHistogram{}, Assumptions: []string{
		"one_canonical_height_is_one_observation_not_one_per_node",
		"header_intervals_have_integer_second_resolution",
		"fixed_margin_pooling_conditions_on_observed_categories_and_run_homogeneity",
		"homogeneity_non_rejection_does_not_prove_within_run_independence",
		"heterogeneous_runs_use_whole_run_labels_and_preserve_within_run_order",
		"non_rejection_does_not_prove_exact_or_physical_equivalence",
	}}
}

// Check distinguishes evidence of a difference from unavailable acceptance.
func (c HeaderTimeComparison) Check() string {
	switch c.Status {
	case "not_distinguishable":
		return "passed"
	case "distinguishable":
		return "failed"
	default:
		return "unproved"
	}
}

// EvaluateBaselineTime uses retained canonical headers and complete baseline
// seeds. Missing historical timestamps cannot establish time acceptance.
func EvaluateBaselineTime(recorded []Height, simulated []SeedResult) (HeaderTimeComparison, error) {
	n := 0
	if len(recorded) > 0 {
		n = 1
	}
	out := newHeaderTimeComparison(n, len(simulated))
	if len(recorded) == 0 {
		out.Issue = "recorded_header_times_unavailable"
		return out, nil
	}
	if len(simulated) < 2 {
		out.Issue = "insufficient_baseline_seeds"
		return out, nil
	}
	return CompareHeaderIntervals([][]Height{recorded}, simulated, 1)
}

// CompareHeaderIntervals extends the established fixed-margin/run-permutation
// baseline method to the complete categorical header-interval distribution.
// Run order is kept intact when heterogeneous runs require label permutation.
func CompareHeaderIntervals(recorded [][]Height, simulated []SeedResult, seed uint64) (HeaderTimeComparison, error) {
	out := newHeaderTimeComparison(len(recorded), len(simulated))
	if len(recorded) < 1 || len(recorded) > 128 || len(simulated) < 2 || len(simulated) > 128 || len(recorded[0]) < 1 || len(recorded[0]) > 10000 {
		return out, errors.New("invalid interval comparison scope")
	}
	scope := recorded[0]
	out.From = scope[0].Number
	out.To = scope[len(scope)-1].Number
	values := map[uint64]bool{}
	tooManyValues := false
	validate := func(heights []Height) error {
		if len(heights) != len(scope) {
			return errors.New("interval run height scope differs")
		}
		for i, h := range heights {
			if h.Number == 0 || h.Number != scope[i].Number || h.PeriodSeconds > h.Time {
				return errors.New("invalid interval height or timestamp")
			}
			if i > 0 && (h.Number <= heights[i-1].Number || h.Number-heights[i-1].Number != 1 || h.Time < heights[i-1].Time || h.PeriodSeconds != h.Time-heights[i-1].Time) {
				return errors.New("interval run contains a gap or inconsistent time")
			}
			if !tooManyValues {
				values[h.PeriodSeconds] = true
				if len(values) > 2048 {
					tooManyValues = true
				}
			}
		}
		return nil
	}
	for _, heights := range recorded {
		if err := validate(heights); err != nil {
			return out, err
		}
	}
	seeds := map[int64]bool{}
	ordered := append([]SeedResult(nil), simulated...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Seed < ordered[j].Seed })
	for _, run := range ordered {
		if seeds[run.Seed] || run.Status != "complete" || run.Violations != 0 {
			return out, errors.New("incomplete or duplicate interval seed")
		}
		seeds[run.Seed] = true
		if err := validate(run.Heights); err != nil {
			return out, err
		}
	}
	if tooManyValues || (len(recorded)+len(simulated))*len(values) > 65536 {
		out.Status = "resource_limit"
		out.Issue = "interval_histogram_dimensions_exceed_limit"
		return out, nil
	}
	seconds := make([]uint64, 0, len(values))
	for n := range values {
		seconds = append(seconds, n)
	}
	sort.Slice(seconds, func(i, j int) bool { return seconds[i] < seconds[j] })
	index := map[uint64]int{}
	for i, n := range seconds {
		index[n] = i
	}
	histogram := func(run, seed string, heights []Height) (IntervalHistogram, []int64) {
		counts := make([]int64, len(seconds))
		for _, h := range heights {
			counts[index[h.PeriodSeconds]]++
		}
		out := IntervalHistogram{Run: run, Seed: seed, Samples: len(heights), Counts: make([]IntervalCount, len(seconds))}
		for i, n := range seconds {
			out.Counts[i] = IntervalCount{Seconds: n, Count: counts[i]}
		}
		return out, counts
	}
	a, b := [][]int64{}, [][]int64{}
	for i, heights := range recorded {
		h, c := histogram("recorded-"+strconv.Itoa(i+1), "", heights)
		out.Recorded = append(out.Recorded, h)
		a = append(a, c)
	}
	for i, run := range ordered {
		h, c := histogram("baseline-"+strconv.Itoa(i+1), strconv.FormatInt(run.Seed, 10), run.Heights)
		out.Simulated = append(out.Simulated, h)
		b = append(b, c)
	}
	pa, pb := make([]int64, len(seconds)), make([]int64, len(seconds))
	for _, row := range a {
		for i, n := range row {
			pa[i] += n
		}
	}
	for _, row := range b {
		for i, n := range row {
			pb[i] += n
		}
	}
	ca, cb := int64(0), int64(0)
	for i := range seconds {
		ca += pa[i]
		cb += pb[i]
		n := ca*int64(len(b)) - cb*int64(len(a))
		if n < 0 {
			n = -n
		}
		d := float64(n) / float64(len(scope)*len(a)*len(b))
		out.MaximumCDFDifference = max(out.MaximumCDFDifference, d)
	}
	ha, err := fixedMarginProbability(a, seed)
	if err != nil {
		return out, err
	}
	out.RecordedHomogeneity = &ha
	out.NumericalErrorProbability += ha.ErrorProbability
	hb, err := fixedMarginProbability(b, seed)
	if err != nil {
		return out, err
	}
	out.SimulatedHomogeneity = &hb
	out.NumericalErrorProbability += hb.ErrorProbability
	da, db := probabilityDecision(ha), probabilityDecision(hb)
	if da == "unavailable" || db == "unavailable" {
		out.Status = "unavailable"
		out.Issue = "interval_run_homogeneity_unavailable"
		return out, nil
	}
	if da == "precision_limited" || db == "precision_limited" {
		out.Status = "precision_limited"
		out.Issue = "interval_run_homogeneity_precision_limited"
		return out, nil
	}
	var comparison ConditionalProbability
	if da == "distinguishable" || db == "distinguishable" {
		if len(a) < 2 {
			out.Status = "insufficient_recorded_runs"
			out.Issue = "heterogeneous_interval_runs_require_recorded_replicates"
			return out, nil
		}
		comparison, err = runCDFProbability(a, b, seed)
	} else {
		comparison, err = fixedMarginProbability([][]int64{pa, pb}, seed)
	}
	if err != nil {
		return out, err
	}
	out.Comparison = &comparison
	out.NumericalErrorProbability += comparison.ErrorProbability
	out.Status = probabilityDecision(comparison)
	if out.Status == "unavailable" {
		out.Issue = comparison.Issue
	}
	return out, nil
}
