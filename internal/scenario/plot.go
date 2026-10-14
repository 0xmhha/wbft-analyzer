package scenario

type Distribution struct {
	Status       string              `json:"status"`
	SavedRuns    int                 `json:"saved_runs"`
	ExpectedRuns int                 `json:"expected_runs"`
	CompleteRuns int                 `json:"complete_runs"`
	Samples      int                 `json:"samples"`
	Issue        string              `json:"issue"`
	Rounds       []DistributionPoint `json:"rounds"`
	Periods      []DistributionPoint `json:"period_seconds"`
	Bands        []SeedBand          `json:"elapsed_seconds"`
}
type ComparisonPlot struct {
	From           uint64       `json:"from,string"`
	To             uint64       `json:"to,string"`
	Credibility    string       `json:"credibility"`
	RecordedSHA    string       `json:"recorded_sha256"`
	Recorded       Distribution `json:"recorded"`
	Baseline       Distribution `json:"baseline"`
	Counterfactual Distribution `json:"counterfactual"`
}

func Plot(e Experiment, baseline, changed []SeedResult) ComparisonPlot {
	out := ComparisonPlot{From: e.From, To: e.To, Credibility: e.Credibility(), RecordedSHA: e.RecordedSHA256}
	observed := []SeedResult{}
	if len(e.RecordedHeights) > 0 {
		observed = append(observed, SeedResult{Seed: 0, Status: "complete", Heights: e.RecordedHeights})
	}
	out.Recorded = distribution(observed, []int64{0}, e.From, e.To)
	if len(observed) == 0 {
		out.Recorded.Status = "unavailable"
		out.Recorded.Issue = "recorded_heights_unavailable"
	}
	out.Baseline = distribution(baseline, e.Provenance.Seeds, e.From, e.To)
	out.Counterfactual = distribution(changed, e.Provenance.Seeds, e.From, e.To)
	return out
}
func distribution(runs []SeedResult, seeds []int64, from, to uint64) Distribution {
	out := Distribution{Status: "incomplete", SavedRuns: len(runs), ExpectedRuns: len(seeds), Rounds: []DistributionPoint{}, Periods: []DistributionPoint{}, Bands: []SeedBand{}, Issue: "seed_executions_incomplete"}
	for _, r := range runs {
		if r.Status == "complete" {
			out.CompleteRuns++
		}
	}
	if from < 1 || to < from || to-from >= 10000 || len(seeds) < 1 || len(seeds) > 128 || len(runs) != len(seeds) {
		return out
	}
	for i, r := range runs {
		if r.Status != "complete" || r.Violations != 0 || r.Seed != seeds[i] || len(r.Heights) != int(to-from+1) {
			return out
		}
		for j, h := range r.Heights {
			if h.Number != from+uint64(j) || h.Time < h.PeriodSeconds || j > 0 && (h.Time < r.Heights[j-1].Time || h.PeriodSeconds != h.Time-r.Heights[j-1].Time) {
				out.Issue = "seed_header_scope_mismatch"
				return out
			}
		}
	}
	rounds, err := RoundECDF(runs)
	if err != nil {
		out.Issue = "distribution_unavailable"
		return out
	}
	periods, err := PeriodECDF(runs)
	if err != nil {
		out.Issue = "distribution_unavailable"
		return out
	}
	bands, err := TimeBands(runs)
	if err != nil {
		out.Issue = "distribution_unavailable"
		return out
	}
	// Values remain exact. Oversized displays are refused without discarding
	// samples or pretending a truncated ECDF represents the complete source.
	if len(rounds) > 10000 || len(periods) > 10000 {
		out.Issue = "distribution_display_bound_exceeded"
		return out
	}
	out.Status = "complete"
	out.Issue = ""
	out.Samples = len(runs) * int(to-from+1)
	out.Rounds = rounds
	out.Periods = periods
	out.Bands = bands
	return out
}
