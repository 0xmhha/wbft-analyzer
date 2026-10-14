package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/replayjob"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/scenariojob"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestScenarioAvailabilityTracksSharedWorkerLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "worker-lifecycle", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	scenarios := scenariojob.NewEmpty(s)
	jobs := replayjob.NewEmpty(s)
	if err := jobs.WithScenarios(scenarios); err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s, Jobs: jobs, Scenarios: scenarios}).Handler()}
	path := fmt.Sprintf("/v1/networks/%d/datasets/%d/scenario-sources", d.NetworkID, d.ID)
	check := func(enabled bool) {
		t.Helper()
		var got ScenarioSources
		if c.do("GET", path, nil, &got) != 200 || got.Enabled != enabled || len(got.Sources) != 0 {
			t.Fatal(got)
		}
	}
	check(false)
	stop, err := jobs.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	check(true)
	stop()
	check(false)
}

func TestScenarioAPIScopedRunsAndSavedSeedPages(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-network-api", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = s.PutMessageInput(ctx, d.ID, messages.Summary{ID: "journal", Kind: "journal", Node: "node", SHA256: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	p, hash, err := scenario.SealProvenance(scenario.Provenance{Dataset: d.ID, Version: scenario.FitVersion, ModelSHA256: strings.Repeat("e", 64), Inputs: []scenario.Input{{ID: "journal", Kind: "journal", Node: "node", SHA256: strings.Repeat("a", 64)}}, ChainSHA256: strings.Repeat("b", 64), CoreCommit: strings.Repeat("c", 40), Seeds: []int64{7, 8}})
	if err != nil {
		t.Fatal(err)
	}
	change := scenario.CutOutgoing{Kind: "cut_outgoing", Node: 0, ToNS: 1000000000}
	_, ch, err := change.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	e := scenario.Experiment{ExecutionSHA256: strings.Repeat("f", 64), From: 1, To: 2, Version: scenario.ExperimentVersion, Provenance: p, SourceSHA256: hash, Change: change, ChangeSHA256: ch, Model: scenario.Assessment{Version: scenario.FitVersion, Status: "partial", Issues: []scenario.Issue{{Code: "synthetic"}}}, RecordedCounts: []scenario.RoundCount{{Total: 100}}}
	job, err := s.EnqueueScenario(ctx, store.ScenarioJob{Dataset: d.ID, Source: "synthetic", SourceSHA: hash, ExecutionSHA: e.ExecutionSHA256, Change: change})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimScenarioJob(ctx, "test-owner")
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.BeginScenarioJob(ctx, claimed.ID, "test-owner", e)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int64{7, 8} {
		result := scenario.SeedResult{Seed: n, Status: "complete", SimulationNS: 1, Heights: []scenario.Height{{Number: 1, Time: math.MaxUint64 - 1, Round: math.MaxUint64, PeriodSeconds: 1}, {Number: 2, Time: math.MaxUint64, Round: 0, PeriodSeconds: 1}}}
		if err = s.PutScenarioSeed(ctx, id, scenario.SeedRecord{Mode: "baseline", Result: result}); err != nil {
			t.Fatal(err)
		}
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d", d.NetworkID, d.ID)
	var sources ScenarioSources
	if c.do("GET", base+"/scenario-sources", nil, &sources) != 200 || len(sources.Sources) != 0 || sources.Enabled {
		t.Fatal(sources)
	}
	if c.do("POST", base+"/scenario-jobs", []byte(`{"source_id":"synthetic","change":{"kind":"cut_outgoing","node":0,"from_ns":0,"to_ns":1000000000}}`), nil) != 503 {
		t.Fatal("disabled worker accepted request")
	}
	var jobs ScenarioJobs
	if c.do("GET", base+"/scenario-jobs", nil, &jobs) != 200 || len(jobs.Jobs) != 1 || jobs.Jobs[0].Run == nil || *jobs.Jobs[0].Run != id {
		t.Fatal(jobs)
	}
	var got store.ScenarioJob
	if c.do("GET", fmt.Sprintf("%s/scenario-jobs/%d", base, job.ID), nil, &got) != 200 || got.Status != "running" {
		t.Fatal(got)
	}
	var runs ScenarioRuns
	if c.do("GET", base+"/scenario-runs", nil, &runs) != 200 || len(runs.Runs) != 1 || runs.Runs[0].Credibility != "execution_incomplete" {
		t.Fatal(runs)
	}
	path := fmt.Sprintf("%s/scenario-runs/%d", base, id)
	var run store.ScenarioRunInfo
	if c.do("GET", path, nil, &run) != 200 || run.Summary.From != 1 {
		t.Fatal(run)
	}
	var page ScenarioSeedPage
	if c.do("GET", path+"/seeds?limit=1", nil, &page) != 200 || len(page.Seeds) != 1 || page.Next == nil || *page.Next != 1 || page.Seeds[0].Result.Heights[0].Round != math.MaxUint64 {
		t.Fatal(page)
	}
	if c.do("GET", path+"/seeds?after=1&limit=1", nil, &page) != 200 || len(page.Seeds) != 1 || page.Next != nil || page.Seeds[0].Index != 2 {
		t.Fatal(page)
	}
	if c.do("GET", path+"/seeds?mode=counterfactual", nil, &page) != 200 || len(page.Seeds) != 0 {
		t.Fatal(page)
	}
	var plot scenario.ComparisonPlot
	if c.do("GET", path+"/comparison", nil, &plot) != 200 || plot.Recorded.Status != "unavailable" || plot.Baseline.Status != "complete" || plot.Baseline.Samples != 4 || plot.Counterfactual.Status != "incomplete" {
		t.Fatal(plot)
	}
	if c.do("GET", path+"/comparison?unexpected=1", nil, nil) != 400 {
		t.Fatal("unexpected plot query")
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/999/datasets/%d/scenario-runs/%d/comparison", d.ID, id), nil, nil) != 404 {
		t.Fatal("cross-network plot exposed")
	}
	for _, suffix := range []string{"?mode=unknown", "?after=-1", "?after=129", "?limit=0", "?limit=129", "?after=1&after=2", "?path=secret"} {
		if c.do("GET", path+"/seeds"+suffix, nil, nil) != 400 {
			t.Fatal("invalid page accepted", suffix)
		}
	}
	for _, suffix := range []string{"/scenario-sources", "/scenario-jobs", "/scenario-runs", fmt.Sprintf("/scenario-jobs/%d", job.ID), fmt.Sprintf("/scenario-runs/%d", id)} {
		if c.do("GET", base+suffix+"?unexpected=1", nil, nil) != 400 {
			t.Fatal("query accepted", suffix)
		}
		wrong := fmt.Sprintf("/v1/networks/999/datasets/%d%s", d.ID, suffix)
		if c.do("GET", wrong, nil, nil) != 404 {
			t.Fatal("cross-network result exposed", suffix)
		}
	}
	other, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "other-network-run", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	for _, suffix := range []string{fmt.Sprintf("/scenario-jobs/%d", job.ID), fmt.Sprintf("/scenario-runs/%d", id), fmt.Sprintf("/scenario-runs/%d/seeds", id)} {
		if c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets/%d%s", other.NetworkID, other.ID, suffix), nil, nil) != 404 {
			t.Fatal("cross-dataset result exposed", suffix)
		}
	}
}
