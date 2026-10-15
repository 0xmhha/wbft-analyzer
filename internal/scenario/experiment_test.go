package scenario

import (
	"context"
	"errors"
	"github.com/0xmhha/wbft/conformance/sim"
	"strings"
	"testing"
	"time"
)

func TestExperimentRetainsFailedBaselineAndCounterfactual(t *testing.T) {
	nodes, links := completeFixture()
	d := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, d, d, sim.Stop{Height: 3, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	sc.WallOrigin = time.Unix(1800000000, 605685000).UTC()
	provenance := Provenance{ModelSHA256: strings.Repeat("e", 64), Dataset: 1, Version: FitVersion, ChainSHA256: strings.Repeat("a", 64), CoreCommit: strings.Repeat("b", 40), Inputs: []Input{{ID: "i", Kind: "journal", Node: "a", SHA256: strings.Repeat("c", 64)}}, Seeds: []int64{1, 2}}
	records := []SeedRecord{}
	result, err := ExecuteExperiment(context.Background(), sc, provenance, Assessment{Version: FitVersion, Status: "partial", Issues: []Issue{{Code: "link_model_unavailable"}}}, []RoundCount{{Late: 300, Total: 300}}, NetworkChange{Kind: "cut_outgoing", Node: new(int), ToNS: int64(time.Minute)}, 1, 3, func(r SeedRecord) error { records = append(records, r); return nil })
	if err != nil || result.Status != "completed" || len(records) != 4 || result.Baseline.Status != "distinguishable" || result.Credibility() != "model_incomplete" {
		t.Fatalf("result %+v %v", result, err)
	}
	if result.WallOrigin != sc.WallOrigin.Format(time.RFC3339Nano) || result.TimeCheck != "unproved" || result.BaselineTime == nil || result.BaselineTime.Issue != "recorded_header_times_unavailable" {
		t.Fatal("clock alignment incorrectly established time acceptance", result.WallOrigin, result.TimeCheck)
	}
	if records[0].Mode != "baseline" || records[2].Mode != "counterfactual" {
		t.Fatal("seed modes mixed")
	}
	sentinel := errors.New("storage stopped")
	result, err = ExecuteExperiment(context.Background(), sc, provenance, Assessment{Version: FitVersion, Status: "complete"}, []RoundCount{{Total: 300}}, NetworkChange{Kind: "cut_outgoing", Node: new(int), ToNS: int64(time.Minute)}, 1, 3, func(SeedRecord) error { return sentinel })
	if !errors.Is(err, sentinel) || result.Status != "partial" || result.Credibility() != "execution_incomplete" {
		t.Fatal("storage failure hidden")
	}
}

func TestExperimentTimeEvidenceRetainsCounterfactualOnFailure(t *testing.T) {
	nodes, links := completeFixture()
	d := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, d, d, sim.Stop{Height: 8, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	p := Provenance{ModelSHA256: strings.Repeat("e", 64), Dataset: 1, Version: FitVersion, ChainSHA256: strings.Repeat("a", 64), CoreCommit: strings.Repeat("b", 40), Inputs: []Input{{ID: "i", Kind: "journal", Node: "a", SHA256: strings.Repeat("c", 64)}}, Seeds: []int64{1, 2}}
	change := NetworkChange{Kind: "cut_outgoing", Node: new(int), ToNS: int64(time.Minute)}
	model := Assessment{Version: FitVersion, Status: "complete"}
	first, err := ExecuteExperiment(context.Background(), sc, p, model, []RoundCount{{Total: 8}}, change, 1, 8, func(SeedRecord) error { return nil })
	if err != nil || len(first.BaselineSeeds) != 2 || first.BaselineSeeds[0].Status != "complete" {
		t.Fatal(first, err)
	}
	heights := append([]Height(nil), first.BaselineSeeds[0].Heights...)
	counts := RoundCount{Total: int64(len(heights))}
	for _, h := range heights {
		if h.Round > 0 {
			counts.Late++
		}
	}
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "matching", true: "different"}[fail], func(t *testing.T) {
			recorded := append([]Height(nil), heights...)
			if fail {
				for i := range recorded {
					recorded[i].PeriodSeconds = 100
					recorded[i].Time = 1800000000 + uint64(i+1)*100
				}
			}
			result, err := ExecuteExperimentWithRecorded(context.Background(), sc, p, model, []RoundCount{counts}, recorded, change, 1, 8, nil, func(SeedRecord) error { return nil })
			wantCheck, wantCredibility := "passed", "baseline_reproduced"
			if fail {
				wantCheck, wantCredibility = "failed", "baseline_time_failed"
			}
			if err != nil || result.Status != "completed" || result.TimeCheck != wantCheck || result.Credibility() != wantCredibility || len(result.ChangedSeeds) != 2 || result.BaselineTime == nil {
				t.Fatalf("baseline evidence or counterfactual lost: %+v %v", result, err)
			}
		})
	}
}
