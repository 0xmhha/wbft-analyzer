package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/replayjob"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/scenariojob"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestScenarioEpochEvidenceJSONContract(t *testing.T) {
	v := ScenarioSources{Sources: []scenariojob.SourceInfo{{TransportInputs: []scenario.Input{}, DeclaredModel: scenario.Assessment{Issues: []scenario.Issue{}}, ApplicationPolicies: []scenario.ApplicationPolicy{}, RuntimeObservations: []scenario.RuntimeBinding{}, Epochs: []scenariojob.EpochInfo{{Block: "18446744073709551615", Candidates: []string{"0x0000000000000000000000000000000000000001"}, Validators: []string{"0x0000000000000000000000000000000000000001"}, HeaderInputsVerified: true}}, Nodes: []string{}, Model: scenario.Assessment{Issues: []scenario.Issue{}}}}}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	s := loadSpec(t)
	sch, err := s.answerSchema("GET", "/v1/networks/1/datasets/2/scenario-sources", 200)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.check(value, sch, "$"); err != nil {
		t.Fatal(err)
	}
}

func TestScenarioSeedExecutionJSONContract(t *testing.T) {
	v := ScenarioSeedPage{Seeds: []store.ScenarioSeed{{Result: scenario.SeedResult{Heights: []scenario.Height{}, Execution: &scenario.SeedExecution{StopHeight: ^uint64(0), DurationNS: 120000000000, Nodes: []scenario.SeedNode{{Index: 0, Address: "simulated-test-node", Head: 9007199254740993}}, Violations: []scenario.SeedViolation{{Kind: "progress", Node: "simulated-test-node", Detail: "head below configured target"}}}, Violations: 1}}}}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"head":"9007199254740993"`)) || !bytes.Contains(raw, []byte(`"configured_stop_height":"18446744073709551615"`)) {
		t.Fatal("large simulator quantities changed JSON representation", string(raw))
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	s := loadSpec(t)
	sch, err := s.answerSchema("GET", "/v1/networks/1/datasets/2/scenario-runs/3/seeds", 200)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.check(value, sch, "$"); err != nil {
		t.Fatal(err)
	}
}

func TestScenarioEmpiricalEvidenceJSONContract(t *testing.T) {
	source := scenario.Input{ID: "synthetic-runtime", Kind: "runtime", Node: "0x1111111111111111111111111111111111111111", SHA256: strings.Repeat("a", 64)}
	timing := scenario.EmpiricalTimings{Source: source, Build: []scenario.AppSample{}, Import: []scenario.AppSample{}, Excluded: []scenario.EmpiricalExcluded{{Kind: "build", ID: "18446744073709551615", Reason: "height_outside_scope", FromLine: 1, ToLine: 2}}, TaskStates: map[string]int{"observed_cancellation": 1}, ImportResults: map[string]int{}}
	app := scenario.AppTiming{Policies: []scenario.ApplicationPolicy{}, Outcomes: []scenario.AppOutcome{}, Build: []scenario.AppSample{}, Import: []scenario.AppSample{}}
	projection := scenario.EmpiricalProjection{Assumptions: []string{"fake_application"}, Nodes: []scenario.EmpiricalNode{{Node: source.Node, Substituted: true, Source: source, Improvements: "18446744073709551615", ParameterEvidence: "static_wbft_parameters_verified"}}, Timings: []scenario.EmpiricalTimings{timing}, Application: app, NativeExcluded: []scenario.AppOutcome{}, Runtimes: []scenario.Runtime{}}
	v := ScenarioSources{Sources: []scenariojob.SourceInfo{{TransportInputs: []scenario.Input{{ID: "synthetic-wire", Kind: "frames", Node: source.Node, SHA256: strings.Repeat("b", 64)}}, Mode: scenario.EmpiricalCoreModel, Empirical: &projection, DeclaredModel: scenario.Assessment{Issues: []scenario.Issue{{Code: "observed_runtime_execution_model_unavailable"}}}, Model: scenario.Assessment{Issues: []scenario.Issue{}}, ApplicationPolicies: []scenario.ApplicationPolicy{}, RuntimeObservations: []scenario.RuntimeBinding{}, Epochs: []scenariojob.EpochInfo{}, Nodes: []string{source.Node}}}}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	sch, err := loadSpec(t).answerSchema("GET", "/v1/networks/1/datasets/2/scenario-sources", 200)
	if err != nil {
		t.Fatal(err)
	}
	if err := loadSpec(t).check(value, sch, "$"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"18446744073709551615"`)) {
		t.Fatal("full-width identifier or mask lost precision")
	}
}

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
	change := scenario.NetworkChange{Kind: "node_lifecycle", ToNS: 1000000000, SchedulePolicy: "replace_window", Lifecycle: []scenario.LifecycleCommand{{Node: new(int), AtNS: new(int64), Action: "stop"}}}
	_, ch, err := change.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	e := scenario.Experiment{ExecutionSHA256: strings.Repeat("f", 64), From: 1, To: 2, Version: scenario.ExperimentVersion, Provenance: p, SourceSHA256: hash, Change: change, ChangeSHA256: ch, Model: scenario.Assessment{Version: scenario.FitVersion, Status: "partial", Issues: []scenario.Issue{{Code: "synthetic"}}}, RecordedCounts: []scenario.RoundCount{{Total: 100}}}
	e.Lifecycle = &scenario.LifecycleEffect{InitialStartsPreserved: true, Retained: 1, Order: "recorded_first_then_intervention", Removed: []scenario.LifecycleRecord{{Node: 0, AtNS: 1, Action: "engine_start"}}}
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
	if run.Summary.Lifecycle == nil || !reflect.DeepEqual(run.Summary.Lifecycle, e.Lifecycle) || run.Summary.Change.Kind != "node_lifecycle" {
		t.Fatal("lifecycle replacement evidence lost", run.Summary.Lifecycle)
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

func TestNetworkChangeRequestJSONContract(t *testing.T) {
	s := loadSpec(t)
	path := "/v1/networks/{net}/datasets/{dataset}/scenario-jobs"
	body := s.Paths[path]["post"].RequestBody.Content["application/json"].Schema
	for _, raw := range []string{
		`{"source_id":"synthetic","change":{"kind":"cut_outgoing","node":0,"from_ns":0,"to_ns":1}}`,
		`{"source_id":"synthetic","change":{"kind":"partition","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}]}}`,
		`{"source_id":"synthetic","change":{"kind":"set_link_delay","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}],"delay_ns":0}}`,
		`{"source_id":"synthetic","change":{"kind":"scale_link_delay","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}],"scale":{"numerator":"9007199254740993","denominator":"1"}}}`,
		`{"source_id":"synthetic","change":{"kind":"node_lifecycle","from_ns":0,"to_ns":1,"schedule_policy":"replace_window","lifecycle":[{"node":0,"at_ns":0,"action":"stop"}]}}`,
	} {
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&v); err != nil {
			t.Fatal(err)
		}
		if err := s.check(v, body, "$"); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{
		`{"source_id":"synthetic","change":{"kind":"partition","node":0,"from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}]}}`,
		`{"source_id":"synthetic","change":{"kind":"cut_outgoing","node":0,"from_ns":0,"to_ns":1,"edges":[]}}`,
		`{"source_id":"synthetic","change":{"kind":"byzantine","node":0,"from_ns":0,"to_ns":1}}`,
		`{"source_id":"synthetic","change":{"kind":"set_link_delay","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}]}}`,
		`{"source_id":"synthetic","change":{"kind":"scale_link_delay","from_ns":0,"to_ns":1,"edges":[{"from":0,"to":1}],"scale":{"numerator":2,"denominator":"1"}}}`,

		`{"source_id":"synthetic","change":{"kind":"partition","from_ns":0,"to_ns":1,"edges":[{"from":null,"to":1}]}}`,
		`{"source_id":"synthetic","change":{"kind":"node_lifecycle","from_ns":0,"to_ns":1,"lifecycle":[{"node":0,"at_ns":0,"action":"stop"}]}}`,
		`{"source_id":"synthetic","change":{"kind":"node_lifecycle","from_ns":0,"to_ns":1,"schedule_policy":"merge","lifecycle":[{"node":0,"at_ns":null,"action":"stop"}]}}`,
		`{"source_id":"synthetic","change":{"kind":"node_lifecycle","from_ns":0,"to_ns":1,"schedule_policy":"merge","lifecycle":[{"node":0,"at_ns":0,"action":"crash"}]}}`,
	} {
		var v any
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&v); err != nil {
			t.Fatal(err)
		}
		if err := s.check(v, body, "$"); err == nil {
			t.Fatal("invalid network change admitted by contract", raw)
		}
	}
}
