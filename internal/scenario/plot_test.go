package scenario

import "testing"

func TestRecordedHeightsBindCountsAndExactScope(t *testing.T) {
	heights := []Height{{Number: 1, Time: 100, PeriodSeconds: 1}, {Number: 2, Round: 1, Time: 102, PeriodSeconds: 2}}
	counts := []RoundCount{{Late: 1, Total: 2}}
	if err := ValidateRecorded(heights, counts, 1, 2); err != nil {
		t.Fatal(err)
	}
	original := RecordedHash(heights)
	for _, change := range []func([]Height){func(h []Height) { h[1].Number = 3 }, func(h []Height) { h[1].Time = 99 }, func(h []Height) { h[1].PeriodSeconds = 1 }} {
		copy := append([]Height(nil), heights...)
		change(copy)
		if err := ValidateRecorded(copy, counts, 1, 2); err == nil {
			t.Fatal("invalid recorded scope accepted")
		}
	}
	if err := ValidateRecorded(heights, []RoundCount{{Total: 2}}, 1, 2); err == nil {
		t.Fatal("counts differ from records")
	}
	changed := append([]Height(nil), heights...)
	changed[0].Round = 1
	if RecordedHash(changed) == original {
		t.Fatal("recorded semantic change not hashed")
	}
}
func TestPlotKeepsMissingAndPartialExecutionsOutOfDistributions(t *testing.T) {
	recorded := []Height{{Number: 1, Time: 100, PeriodSeconds: 1}, {Number: 2, Round: 1, Time: 102, PeriodSeconds: 2}}
	e := Experiment{From: 1, To: 2, Status: "completed", RecordedHeights: recorded, RecordedSHA256: RecordedHash(recorded), Provenance: Provenance{Seeds: []int64{7, 8}}, Model: Assessment{Status: "partial"}}
	a := SeedResult{Seed: 7, Status: "complete", Heights: []Height{{Number: 1, Time: 200, PeriodSeconds: 1}, {Number: 2, Time: 201, PeriodSeconds: 1}}}
	b := SeedResult{Seed: 8, Status: "complete", Heights: []Height{{Number: 1, Time: 300, PeriodSeconds: 1}, {Number: 2, Round: 2, Time: 304, PeriodSeconds: 4}}}
	plot := Plot(e, []SeedResult{a, b}, []SeedResult{a})
	if plot.Recorded.Samples != 2 || plot.Baseline.Samples != 4 || plot.Baseline.Rounds[0].Cumulative != 0.75 || plot.Baseline.Bands[1].Maximum != 4 || plot.Counterfactual.Status != "incomplete" || len(plot.Counterfactual.Rounds) != 0 {
		t.Fatalf("plot %+v", plot)
	}
	b.Status = "partial"
	plot = Plot(e, []SeedResult{a, b}, nil)
	if plot.Baseline.Samples != 0 || len(plot.Baseline.Rounds) != 0 || plot.Baseline.SavedRuns != 2 || plot.Baseline.CompleteRuns != 1 {
		t.Fatal("partial suffix silently excluded")
	}
	b.Status = "complete"
	b.Seed = 7
	if Plot(e, []SeedResult{a, b}, nil).Baseline.Status == "complete" {
		t.Fatal("wrong or duplicate seed accepted")
	}
	e.RecordedHeights = nil
	if Plot(e, nil, nil).Recorded.Status != "unavailable" {
		t.Fatal("recorded heights invented from counts")
	}
}
