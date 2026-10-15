package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
)

func scenarioFixture(dataset int64) (scenario.Experiment, ScenarioJob) {
	p := scenario.Provenance{ModelSHA256: strings.Repeat("e", 64), Dataset: dataset, Version: scenario.FitVersion, Inputs: []scenario.Input{{ID: "journal", Kind: "journal", Node: "a", SHA256: strings.Repeat("a", 64)}}, ChainSHA256: strings.Repeat("b", 64), CoreCommit: strings.Repeat("c", 40), Seeds: []int64{7, 8}}
	p, hash, _ := scenario.SealProvenance(p)
	change := scenario.NetworkChange{Kind: "cut_outgoing", Node: new(int), ToNS: 1000000000}
	_, ch, _ := change.Canonical()
	e := scenario.Experiment{ExecutionSHA256: strings.Repeat("f", 64), From: 1, To: 2, Version: scenario.ExperimentVersion, Provenance: p, SourceSHA256: hash, Change: change, ChangeSHA256: ch, Model: scenario.Assessment{Version: scenario.FitVersion, Status: "partial", Issues: []scenario.Issue{{Code: "synthetic"}}}, RecordedCounts: []scenario.RoundCount{{Total: 100}}}
	return e, ScenarioJob{Dataset: dataset, Source: "source", SourceSHA: hash, ExecutionSHA: e.ExecutionSHA256, Change: change}
}

func TestScenarioQueueSharesBoundAndPreservesInterruptedPrefix(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	initial, job := scenarioFixture(dataset)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			_, err := s.EnqueueScenario(ctx, job)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrReexecQueueFull) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != MaxReexecJobs {
		t.Fatalf("accepted %d", accepted.Load())
	}
	if _, err := s.EnqueueReexec(ctx, testJob(dataset)); !errors.Is(err, ErrReexecQueueFull) {
		t.Fatal("replay bypassed common queue bound", err)
	}
	if _, err := s.EnqueueWhatif(ctx, WhatifJob{}); err == nil {
		t.Fatal("invalid timer job accepted")
	}
	claimed, err := s.ClaimScenarioJob(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	wrong := initial
	wrong.ExecutionSHA256 = strings.Repeat("0", 64)
	if _, err := s.BeginScenarioJob(ctx, claimed.ID, "owner", wrong); err == nil {
		t.Fatal("different execution linked")
	}
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM scenario_runs`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unlinked run survived failed transaction", err)
	}
	id, err := s.BeginScenarioJob(ctx, claimed.ID, "owner", initial)
	if err != nil {
		t.Fatal(err)
	}
	seed := scenario.SeedResult{Seed: 7, Status: "complete", SimulationNS: 1, Heights: []scenario.Height{{Number: 1, Time: 1, PeriodSeconds: 1}, {Number: 2, Time: 2, PeriodSeconds: 1}}}
	if err := s.PutScenarioSeed(ctx, id, scenario.SeedRecord{Mode: "baseline", Result: seed}); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishScenarioJob(ctx, claimed.ID, "other", "failed", "worker_interrupted"); err == nil {
		t.Fatal("wrong owner finalised job")
	}
	if err := s.FinishScenarioJob(ctx, claimed.ID, "owner", "succeeded", ""); err == nil {
		t.Fatal("unfinished run marked success")
	}
	lease, err := s.ReexecWorkerLease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close(ctx)
	if err := s.RecoverScenarioJobs(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.ScenarioJob(ctx, dataset, claimed.ID)
	if err != nil || recovered.Status != "failed" || recovered.Issue != "worker_interrupted" {
		t.Fatal("recovery", err)
	}
	summary, err := s.ScenarioRun(ctx, dataset, id)
	if err != nil || summary.Status != "partial" {
		t.Fatal("partial run lost", err)
	}
	rows, err := s.ScenarioSeeds(ctx, dataset, id, "baseline", 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatal("saved prefix lost", err)
	}
	pending, err := s.ScenarioJobs(ctx, dataset)
	if err != nil || len(pending) != 32 {
		t.Fatal("queued work lost", err)
	}
	if _, err := s.ScenarioJob(ctx, dataset+1, claimed.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-dataset job visible")
	}
}

func TestScenarioClaimFencedByDatasetDeletionAndActiveRun(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, _, _ := ownedDataset(t, s, "synthetic-scenario-deletion", t.TempDir())
	e, j := scenarioFixture(d.ID)
	queued, err := s.EnqueueScenario(ctx, j)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := s.datasetLease(ctx, d.ID, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimScenarioJob(ctx, "owner"); !errors.Is(err, ErrNotFound) {
		t.Fatal("claim crossed exclusive dataset fence", err)
	}
	fence()
	claimed, err := s.ClaimScenarioJob(ctx, "owner")
	if err != nil || claimed.ID != queued.ID {
		t.Fatal(claimed, err)
	}
	if _, err = s.DeleteDataset(ctx, d.NetworkID, d.ID, d.Name); !errors.Is(err, ErrDatasetBusy) {
		t.Fatal("active job deleted", err)
	}
	id, err := s.BeginScenarioJob(ctx, claimed.ID, "owner", e)
	if err != nil {
		t.Fatal(err)
	}
	e.Status = "partial"
	if err = s.FinishScenario(ctx, id, e); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishScenarioJob(ctx, claimed.ID, "owner", "failed", "synthetic_stop"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.EnqueueScenario(ctx, j); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DeleteDataset(ctx, d.NetworkID, d.ID, d.Name); err != nil {
		t.Fatal("linked runs or queued jobs prevented owned deletion", err)
	}
	if _, err = s.ScenarioJob(ctx, d.ID, claimed.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted job remains", err)
	}
	if _, err = s.ScenarioRun(ctx, d.ID, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted run remains", err)
	}
	if _, err = s.ClaimScenarioJob(ctx, "owner"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted job claimed", err)
	}
}
