package scenario

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

func empiricalFitFixture(t *testing.T) FitOptions {
	t.Helper()
	return empiricalFitFixtureAt(t, sim.Epoch)
}

func empiricalFitFixtureAt(t *testing.T, origin time.Time) FitOptions {
	return empiricalFitFixtureWithSettings(t, origin, nil, nil)
}

func empiricalFitFixtureWithSettings(t *testing.T, origin time.Time, rules map[types.RuleName]string, future *uint64) FitOptions {
	t.Helper()
	nodes, links := completeFixture()
	d := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, d, d, sim.Stop{Height: 6, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	sc.WallOrigin = origin
	sc.Params.RuleActivations = rules
	sc.Params.AllowedFutureBlockTime = future
	journalDir := t.TempDir()
	result, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: journalDir})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := os.ReadFile(filepath.Join(journalDir, "chain.rlp"))
	if err != nil {
		t.Fatal(err)
	}
	out := FitOptions{Model: EmpiricalCoreModel, Dataset: 1, Chain: chain, Origin: origin, Clock: pairs.Clock{Model: "shared-host"}, From: 2, To: 4, Until: time.Minute, CoreCommit: strings.Repeat("b", 40), Seeds: []int64{1, 2}}
	for i, key := range sc.Validators {
		node := strings.ToLower(key.Address().Hex())
		input := messages.Input{ID: string(rune('a' + i)), Kind: "journal", Node: node, Path: filepath.Join(journalDir, hex.EncodeToString(key.Address().Bytes()))}
		summary, err := messages.Fingerprint(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		out.Journals = append(out.Journals, messages.Prepared{Input: input, Summary: summary})
		out.Coverage = append(out.Coverage, Coverage{Node: node, From: origin, To: origin.Add(time.Minute), SettledThrough: origin.Add(time.Minute), Complete: true})
	}
	for _, raw := range result.Events {
		var first struct {
			Node string `json:"node"`
		}
		if err := json.Unmarshal(bytes.SplitN(raw, []byte("\n"), 2)[0], &first); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		events, err := InspectEvents(context.Background(), Input{ID: "events-" + first.Node[2:], Kind: "events", Node: first.Node, SHA256: hex.EncodeToString(digest[:])}, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		out.Events = append(out.Events, events)
	}
	return out
}

func TestEmpiricalModeIsExplicitAndKeepsDeclaredAssessment(t *testing.T) {
	o := empiricalFitFixture(t)
	got, err := Fit(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != EmpiricalCoreModel || got.Model.Status != "complete" || got.Scenario == nil || got.Empirical == nil || got.DeclaredModel.Status != "partial" {
		for _, l := range got.Links {
			t.Log(l.Sender, l.Receiver, l.Observed, l.Unproved, l.Status)
		}
		t.Fatalf("%+v; declared %+v", got.Model, got.DeclaredModel)
	}
	for _, n := range got.Empirical.Nodes {
		if n.Substituted || n.ApplicationPolicy != "independent_request_sampled_empty_body" || n.ParameterEvidence != "journal_scope_parameters_verified" || n.SigningState != "recorded_none" {
			t.Fatal(n)
		}
	}
	for _, n := range got.Scenario.Nodes {
		if n.BuildQueuePolicy != "" || len(n.BuildDelay) == 0 || len(n.ImportDelay) == 0 {
			t.Fatal(n)
		}
	}
	if err := RunSeeds(context.Background(), *got.Scenario, o.Seeds, o.From, o.To, func(r SeedResult) error {
		if r.Status != "complete" {
			t.Fatal(r)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i := len(o.Journals) - 1; i >= 0; i-- {
		o.TransportInputs = append(o.TransportInputs, o.Journals[i].Summary.ID)
	}
	selected, err := Fit(context.Background(), o)
	if err != nil || selected.Model.Status != "complete" || selected.Scenario == nil || selected.SourceSHA256 != got.SourceSHA256 {
		t.Fatal("equivalent explicit transport selection changed the executable model", selected.Model, err)
	}
	o.TransportInputs = o.TransportInputs[:len(o.TransportInputs)-1]
	incomplete, err := Fit(context.Background(), o)
	if err != nil || incomplete.Model.Status != "partial" || incomplete.Scenario != nil || len(incomplete.Provenance.Inputs) != len(got.Provenance.Inputs) {
		t.Fatal("missing transport node inferred or evidence dropped", incomplete.Model, err)
	}
	o.TransportInputs = nil
	o.Model = ""
	strict, err := Fit(context.Background(), o)
	if err != nil || strict.Mode != DeclaredRuntimeModel || strict.Empirical != nil || strict.Model.Status != "partial" || strict.Scenario != nil || strict.SourceSHA256 == got.SourceSHA256 || strict.Provenance.ModelSHA256 == got.Provenance.ModelSHA256 {
		t.Fatal("mode or model identity lost", strict.Model, err)
	}
	o.Model = "unknown"
	if _, err := Fit(context.Background(), o); err == nil {
		t.Fatal("unknown model accepted")
	}
}

func TestEmpiricalModeKeepsRealMissingEvidenceGates(t *testing.T) {
	o := empiricalFitFixture(t)
	o.Coverage = nil
	got, err := Fit(context.Background(), o)
	if err != nil || got.Model.Status != "partial" || got.Scenario != nil {
		t.Fatal(got.Model, err)
	}
	found := false
	for _, issue := range got.Model.Issues {
		found = found || issue.Code == "link_model_unavailable"
	}
	if !found {
		t.Fatal(got.Model)
	}
	o = empiricalFitFixture(t)
	o.Events = o.Events[:len(o.Events)-1]
	got, err = Fit(context.Background(), o)
	if err != nil || got.Model.Status != "partial" || got.Scenario != nil {
		t.Fatal(got.Model, err)
	}
	found = false
	for _, issue := range got.Model.Issues {
		found = found || issue.Code == "native_runtime_unavailable"
	}
	if !found {
		t.Fatal(got.Model)
	}
}

func TestSubstituteLifecycleUsesOriginalCoreBoundaries(t *testing.T) {
	in := empiricalFixture(t, false)
	origin := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := fitSubstituteRuntime(in, origin, time.Second)
	if err != nil || got.Starts != 1 || got.StartNS != 0 || len(got.Events) != 1 || got.Events[0].Action != "stop" || got.Events[0].Line != 21 || got.ReplayWAL == nil || *got.ReplayWAL {
		t.Fatal(got, err)
	}
	in.Capture.Engines[0].Stages[0].Wall = "2026-01-02T00:00:00Z"
	if _, err := fitSubstituteRuntime(in, origin, time.Second); err == nil {
		t.Fatal("altered stage accepted")
	}
}

func TestEmpiricalCoreSubstitutionRequiresExplicitModeAndAllFlagsOff(t *testing.T) {
	nodes, links := completeFixture()
	nodes[0].ProfileEvidence = "modeled_core_substitution"
	nodes[0].RuntimeEvidence = "modeled_core_substitution"
	nodes[0].Improvements = 0
	nodes[0].ReplayWAL = false
	params := sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}
	delay := []time.Duration{time.Millisecond}
	stop := sim.Stop{Height: 3, Duration: time.Minute}
	if _, err := Build(nodes, links, params, delay, delay, stop); err == nil {
		t.Fatal("substitution passed as recorded runtime")
	}
	sc, err := buildScenario(nodes, links, params, delay, delay, stop, EmpiricalCoreModel)
	if err != nil || sc.Nodes[0].Options.Improvements != 0 || sc.Nodes[0].ReplayWAL {
		t.Fatal(sc, err)
	}
	if err := RunSeeds(context.Background(), sc, []int64{1}, 1, 3, func(r SeedResult) error {
		if r.Status != "complete" {
			t.Fatal(r)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	nodes[0].Improvements = 1
	if _, err := buildScenario(nodes, links, params, delay, delay, stop, EmpiricalCoreModel); err == nil {
		t.Fatal("substitution silently enabled an improvement")
	}
	nodes[0].Improvements = 0
	nodes[0].ReplayWAL = true
	if _, err := buildScenario(nodes, links, params, delay, delay, stop, EmpiricalCoreModel); err == nil {
		t.Fatal("substitution silently enabled replay")
	}
}

func TestFittingPreservesRecordedFractionalWallOrigin(t *testing.T) {
	origin := time.Unix(1800000000, 605685000).UTC()
	options := empiricalFitFixtureAt(t, origin)
	fitted, err := Fit(context.Background(), options)
	if err != nil || fitted.Scenario == nil || fitted.Model.Status != "complete" {
		t.Fatal("recorded origin could not be fitted", fitted.Model, err)
	}
	if fitted.WallOrigin != origin.Format(time.RFC3339Nano) || !fitted.Scenario.WallOrigin.Equal(origin) {
		t.Fatal("recorded clock phase was discarded", fitted.WallOrigin, fitted.Scenario.WallOrigin)
	}
	result, err := sim.Run(context.Background(), *fitted.Scenario, sim.Output{})
	if err != nil || len(result.Violations) > 0 {
		t.Fatal("fitted run failed", err)
	}
	if result.Chain[0].Header.Time != uint64(origin.Unix())-1 {
		t.Fatal("fitted genesis used the default clock")
	}
	for _, raw := range result.Events {
		for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
			var event struct {
				Wall string `json:"t_wall"`
				Mono int64  `json:"t_mono_ns"`
			}
			if err := json.Unmarshal(line, &event); err != nil {
				t.Fatal(err)
			}
			wall, err := time.Parse(time.RFC3339Nano, event.Wall)
			if err != nil || !wall.Equal(origin.Add(time.Duration(event.Mono))) {
				t.Fatal("fitted node lost recorded clock phase", event, err)
			}
		}
	}
}
