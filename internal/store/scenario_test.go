package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
)

func TestExperimentV2KeepsTimeCriterionAcrossFittingVersions(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	e, _ := scenarioFixture(dataset)
	heights := []scenario.Height{{Number: 1, Time: 1, PeriodSeconds: 1}, {Number: 2, Time: 2, PeriodSeconds: 1}}
	e.RecordedHeights, e.RecordedCounts = heights, []scenario.RoundCount{{Total: 2}}
	e.Model.Status, e.Model.Issues = "complete", []scenario.Issue{}
	id, err := s.BeginScenario(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.ScenarioRun(ctx, dataset, id)
	if err != nil {
		t.Fatal(err)
	}
	old.Model.Version, old.Provenance.Version = "wbft-network-scenario-fit/15", "wbft-network-scenario-fit/15"
	provenance, err := json.Marshal(old.Provenance)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(provenance)
	old.SourceSHA256 = hex.EncodeToString(sum[:])
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE scenario_runs SET provenance=$2,source_sha256=$3,summary=$4 WHERE id=$1`, id, provenance, old.SourceSHA256, raw); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"baseline", "counterfactual"} {
		for _, seed := range old.Provenance.Seeds {
			if err := s.PutScenarioSeed(ctx, id, scenario.SeedRecord{Mode: mode, Result: scenario.SeedResult{Seed: seed, Status: "complete", Heights: heights}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	old.Status, old.TimeCheck = "completed", "failed"
	if err := s.FinishScenario(ctx, id, old); err != nil {
		t.Fatal(err)
	}
	final, err := s.ScenarioRun(ctx, dataset, id)
	if err != nil || final.Model.Version != old.Model.Version || final.TimeCheck != "passed" || final.BaselineTime == nil || final.BaselineTime.Method != scenario.HeaderTimeBaselineMethod || final.Credibility() != "baseline_reproduced" {
		t.Fatal("criterion changed with fitting implementation", final, err)
	}
}

func TestScenarioProcessingModelCannotChangeDuringFinalization(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	e, _ := scenarioFixture(jobDataset(t, s))
	e.Model.Processing = &scenario.ProcessingModel{Policy: scenario.NativeProcessingPolicy, Workers: 1, Timings: []scenario.ProcessingTimings{}, Assumptions: []string{"receive_worker_count_is_declared_not_measured"}}
	id, err := s.BeginScenario(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := s.ScenarioRun(ctx, e.Provenance.Dataset, id)
	if err != nil || !reflect.DeepEqual(stored.Model.Processing, e.Model.Processing) {
		t.Fatal("processing model not retained", stored, err)
	}
	stored.Status = "partial"
	stored.Model.Processing.Workers++
	if err := s.FinishScenario(ctx, id, stored); err != ErrScenarioState {
		t.Fatal("changed processing model accepted", err)
	}
	stored.Model.Processing.Workers--
	if err := s.FinishScenario(ctx, id, stored); err != nil {
		t.Fatal(err)
	}
}

func TestScenarioTimeProofIsRecomputedFromRetainedRows(t *testing.T) {
	for _, different := range []bool{false, true} {
		t.Run(map[bool]string{false: "matching", true: "different"}[different], func(t *testing.T) {
			s, _ := testStore(t)
			ctx := context.Background()
			if _, err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			dataset := jobDataset(t, s)
			e, _ := scenarioFixture(dataset)
			e.To = 64
			e.Model.Status, e.Model.Issues = "complete", []scenario.Issue{}
			e.RecordedCounts = []scenario.RoundCount{{Total: 64}}
			e.RecordedHeights = make([]scenario.Height, 64)
			baseline := make([]scenario.Height, 64)
			period := uint64(1)
			if different {
				period = 3
			}
			for i := range baseline {
				n := uint64(i + 1)
				baseline[i] = scenario.Height{Number: n, Time: 1700000000 + n, PeriodSeconds: 1}
				e.RecordedHeights[i] = scenario.Height{Number: n, Time: 1700000000 + n*period, PeriodSeconds: period}
			}
			e.TimeCheck = "passed"
			e.BaselineTime = &scenario.HeaderTimeComparison{Status: "not_distinguishable"}
			id, err := s.BeginScenario(ctx, e)
			if err != nil {
				t.Fatal(err)
			}
			initial, err := s.ScenarioRun(ctx, dataset, id)
			if err != nil || initial.TimeCheck != "pending" || initial.BaselineTime != nil {
				t.Fatal("producer's premature acceptance retained", initial, err)
			}
			for _, mode := range []string{"baseline", "counterfactual"} {
				for _, seed := range e.Provenance.Seeds {
					if err := s.PutScenarioSeed(ctx, id, scenario.SeedRecord{Mode: mode, Result: scenario.SeedResult{Seed: seed, Status: "complete", Heights: baseline}}); err != nil {
						t.Fatal(err)
					}
				}
			}
			e.Status = "completed"
			if !different {
				e.TimeCheck, e.BaselineTime.Status = "failed", "distinguishable"
			}
			if err := s.FinishScenario(ctx, id, e); err != nil {
				t.Fatal(err)
			}
			final, err := s.ScenarioRun(ctx, dataset, id)
			check, credibility := "passed", "baseline_reproduced"
			if different {
				check, credibility = "failed", "baseline_time_failed"
			}
			if err != nil || final.TimeCheck != check || final.Credibility() != credibility || final.BaselineTime == nil || final.BaselineTime.Method != scenario.HeaderTimeBaselineMethod || len(final.BaselineTime.Simulated) != 2 || final.RecordedSHA256 != scenario.RecordedHash(e.RecordedHeights) {
				t.Fatalf("unverified time proof retained: %+v %v", final, err)
			}
		})
	}
}

func TestHistoricalScenarioTimeCriteriaAreNotReinterpreted(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	e, _ := scenarioFixture(dataset)
	id, err := s.BeginScenario(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.ScenarioRun(ctx, dataset, id)
	if err != nil {
		t.Fatal(err)
	}
	old.Version = "wbft-network-experiment/1"
	old.Model.Version = "wbft-network-scenario-fit/14"
	old.TimeCheck = "threshold_unconfigured"
	raw, _ := json.Marshal(old)
	if _, err := s.pool.Exec(ctx, `UPDATE scenario_runs SET summary=$2 WHERE id=$1`, id, raw); err != nil {
		t.Fatal(err)
	}
	saved, err := s.ScenarioRun(ctx, dataset, id)
	if err != nil || !reflect.DeepEqual(old, saved) {
		t.Fatal("historical summary changed on read", saved, err)
	}
	for _, mode := range []string{"baseline", "counterfactual"} {
		for _, seed := range old.Provenance.Seeds {
			heights := []scenario.Height{{Number: 1, Time: 1, PeriodSeconds: 1}, {Number: 2, Time: 2, PeriodSeconds: 1}}
			if err := s.PutScenarioSeed(ctx, id, scenario.SeedRecord{Mode: mode, Result: scenario.SeedResult{Seed: seed, Status: "complete", Heights: heights}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	saved.Status, saved.TimeCheck = "completed", "passed"
	saved.BaselineTime = &scenario.HeaderTimeComparison{Status: "not_distinguishable"}
	if err := s.FinishScenario(ctx, id, saved); err != nil {
		t.Fatal(err)
	}
	final, err := s.ScenarioRun(ctx, dataset, id)
	if err != nil || final.Version != old.Version || final.TimeCheck != old.TimeCheck || final.BaselineTime != nil {
		t.Fatal("historical criteria silently upgraded", final, err)
	}
}

func TestScenarioEmpiricalProvenanceSurvivesPersistenceAndKeepsOriginalAssumptions(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	e, _ := scenarioFixture(dataset)
	e.Provenance.Mode = scenario.EmpiricalCoreModel
	e.Provenance.Assumptions = []string{"fake_application", "fresh_test_keys"}
	input := scenario.Input{ID: "wire", Kind: "frames", Node: "substitute", SHA256: strings.Repeat("a", 64)}
	e.Provenance.Inputs = append(e.Provenance.Inputs, input)
	e.Provenance.Substitutions = []scenario.CoreSubstitution{{Node: input.Node, Source: input, Policy: "all_improvements_off", SigningState: "fresh_test_keys_genesis_no_replay"}}
	var err error
	e.Provenance, e.SourceSHA256, err = scenario.SealProvenance(e.Provenance)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.BeginScenario(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := s.ScenarioRun(ctx, dataset, id)
	if err != nil || !reflect.DeepEqual(saved.Provenance, e.Provenance) {
		t.Fatal(saved.Provenance, err)
	}
	changed := e
	changed.Status = "partial"
	changed.Provenance.Assumptions = []string{"different_application"}
	if err := s.FinishScenario(ctx, id, changed); err != nil {
		t.Fatal(err)
	}
	saved, err = s.ScenarioRun(ctx, dataset, id)
	if err != nil || !reflect.DeepEqual(saved.Provenance, e.Provenance) || saved.Credibility() != "execution_incomplete" {
		t.Fatal(saved, err)
	}
}

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
	e.BaselineTime = &scenario.HeaderTimeComparison{Status: "not_distinguishable"}
	e.Baseline = &scenario.RoundComparison{Status: "distinguishable"}
	if err := s.FinishScenario(ctx, id, e); err != nil {
		t.Fatal(err)
	}
	final, err := s.ScenarioRun(ctx, dataset, id)
	if err != nil || final.TimeCheck != "unproved" || final.BaselineTime == nil || final.BaselineTime.Issue != "recorded_header_times_unavailable" || final.Baseline.Status != "not_distinguishable" || final.Credibility() != "model_incomplete" {
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
