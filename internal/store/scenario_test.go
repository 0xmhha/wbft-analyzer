package store

import (
	"context"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
)

func TestScenarioSeedTransactionsAndCompletionProof(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	p := scenario.Provenance{ModelSHA256: strings.Repeat("e", 64), Dataset: dataset, Version: scenario.FitVersion, Inputs: []scenario.Input{{ID: "journal", Kind: "journal", Node: "a", SHA256: strings.Repeat("a", 64)}}, ChainSHA256: strings.Repeat("b", 64), CoreCommit: strings.Repeat("c", 40), Seeds: []int64{7, 8}}
	p, hash, err := scenario.SealProvenance(p)
	if err != nil {
		t.Fatal(err)
	}
	change := scenario.CutOutgoing{Kind: "cut_outgoing", Node: 0, ToNS: 1000000000}
	_, changeHash, _ := change.Canonical()
	e := scenario.Experiment{ExecutionSHA256: strings.Repeat("f", 64), From: 1, To: 2, Version: scenario.ExperimentVersion, Provenance: p, SourceSHA256: hash, Change: change, ChangeSHA256: changeHash, Model: scenario.Assessment{Version: scenario.FitVersion, Status: "partial", Issues: []scenario.Issue{{Code: "synthetic"}}}, RecordedCounts: []scenario.RoundCount{{Total: 100}}}
	id, err := s.BeginScenario(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	e.Status = "completed"
	if err := s.FinishScenario(ctx, id, e); err == nil {
		t.Fatal("empty completion accepted")
	}
	seed := scenario.SeedResult{Seed: 8, Status: "complete", SimulationNS: 1, Heights: []scenario.Height{{Number: 1, Time: 1, PeriodSeconds: 1}, {Number: 2, Time: 2, PeriodSeconds: 1}}}
	if err := s.PutScenarioSeed(ctx, id, scenario.SeedRecord{Mode: "baseline", Result: seed}); err == nil {
		t.Fatal("seed order skipped")
	}
	rows, err := s.ScenarioSeeds(ctx, dataset, id, "baseline", 0, 10)
	if err != nil || len(rows) != 0 {
		t.Fatal("failed seed transaction left rows", err)
	}
	seed.Seed = 7
	if err := s.PutScenarioSeed(ctx, id, scenario.SeedRecord{Mode: "counterfactual", Result: seed}); err == nil {
		t.Fatal("counterfactual before baseline accepted")
	}
	for _, mode := range []string{"baseline", "counterfactual"} {
		for _, n := range []int64{7, 8} {
			seed.Seed = n
			if err := s.PutScenarioSeed(ctx, id, scenario.SeedRecord{Mode: mode, Result: seed}); err != nil {
				t.Fatal(err)
			}
		}
	}
	e.TimeCheck = "passed"
	e.Baseline = &scenario.RoundComparison{Status: "distinguishable"}
	if err := s.FinishScenario(ctx, id, e); err != nil {
		t.Fatal(err)
	}
	final, err := s.ScenarioRun(ctx, dataset, id)
	if err != nil || final.TimeCheck != "threshold_unconfigured" || final.Baseline.Status != "not_distinguishable" || final.Credibility() != "model_incomplete" {
		t.Fatalf("false proof retained %+v %v", final, err)
	}
	if err := s.PutScenarioSeed(ctx, id, scenario.SeedRecord{Mode: "baseline", Result: seed}); err == nil {
		t.Fatal("append after completion")
	}
	if _, err := s.ScenarioRun(ctx, dataset+1, id); err != ErrNotFound {
		t.Fatal("cross-dataset run visible")
	}
}

func TestScenarioRecordedSeriesIsImmutableAndPlottedWithoutPartialPooling(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	e, _ := scenarioFixture(dataset)
	e.RecordedHeights = []scenario.Height{{Number: 1, Time: 100, PeriodSeconds: 1}, {Number: 2, Round: 1, Time: 102, PeriodSeconds: 2}}
	e.RecordedCounts = []scenario.RoundCount{{Late: 1, Total: 2}}
	invalid := e
	invalid.RecordedCounts = []scenario.RoundCount{{Total: 2}}
	if _, err := s.BeginScenario(ctx, invalid); err == nil {
		t.Fatal("fake observed counts accepted")
	}
	invalid = e
	invalid.RecordedSHA256 = strings.Repeat("0", 64)
	if _, err := s.BeginScenario(ctx, invalid); err == nil {
		t.Fatal("fake observed hash accepted")
	}
	id, err := s.BeginScenario(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := s.ScenarioPlot(ctx, dataset, id)
	if err != nil || initial.Recorded.Samples != 2 || initial.Baseline.Status != "incomplete" {
		t.Fatal(initial, err)
	}
	for _, seed := range e.Provenance.Seeds {
		r := scenario.SeedResult{Seed: seed, Status: "complete", SimulationNS: 1, Heights: append([]scenario.Height(nil), e.RecordedHeights...)}
		if err := s.PutScenarioSeed(ctx, id, scenario.SeedRecord{Mode: "baseline", Result: r}); err != nil {
			t.Fatal(err)
		}
	}
	changed := e
	changed.Status = "partial"
	changed.RecordedHeights = append([]scenario.Height(nil), e.RecordedHeights...)
	changed.RecordedHeights[0].Round = 1
	if err := s.FinishScenario(ctx, id, changed); err == nil {
		t.Fatal("recorded series changed during finalization")
	}
	e.Status = "partial"
	if err := s.FinishScenario(ctx, id, e); err != nil {
		t.Fatal(err)
	}
	final, err := s.ScenarioRun(ctx, dataset, id)
	if err != nil || final.RecordedSHA256 != scenario.RecordedHash(e.RecordedHeights) {
		t.Fatal(final, err)
	}
	plot, err := s.ScenarioPlot(ctx, dataset, id)
	if err != nil || plot.Recorded.Samples != 2 || plot.Baseline.Samples != 4 || plot.Counterfactual.Samples != 0 || plot.Counterfactual.Status != "incomplete" || plot.Credibility != "execution_incomplete" {
		t.Fatal(plot, err)
	}
	if _, err := s.ScenarioPlot(ctx, dataset+1, id); err != ErrNotFound {
		t.Fatal("cross-dataset plot exposed", err)
	}
}
