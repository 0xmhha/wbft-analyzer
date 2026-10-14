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
	provenance := Provenance{ModelSHA256: strings.Repeat("e", 64), Dataset: 1, Version: FitVersion, ChainSHA256: strings.Repeat("a", 64), CoreCommit: strings.Repeat("b", 40), Inputs: []Input{{ID: "i", Kind: "journal", Node: "a", SHA256: strings.Repeat("c", 64)}}, Seeds: []int64{1, 2}}
	records := []SeedRecord{}
	result, err := ExecuteExperiment(context.Background(), sc, provenance, Assessment{Version: FitVersion, Status: "partial", Issues: []Issue{{Code: "link_model_unavailable"}}}, []RoundCount{{Late: 300, Total: 300}}, CutOutgoing{Kind: "cut_outgoing", Node: 0, ToNS: int64(time.Minute)}, 1, 3, func(r SeedRecord) error { records = append(records, r); return nil })
	if err != nil || result.Status != "completed" || len(records) != 4 || result.Baseline.Status != "distinguishable" || result.Credibility() != "model_incomplete" {
		t.Fatalf("result %+v %v", result, err)
	}
	if records[0].Mode != "baseline" || records[2].Mode != "counterfactual" {
		t.Fatal("seed modes mixed")
	}
	sentinel := errors.New("storage stopped")
	result, err = ExecuteExperiment(context.Background(), sc, provenance, Assessment{Version: FitVersion, Status: "complete"}, []RoundCount{{Total: 300}}, CutOutgoing{Kind: "cut_outgoing", Node: 0, ToNS: int64(time.Minute)}, 1, 3, func(SeedRecord) error { return sentinel })
	if !errors.Is(err, sentinel) || result.Status != "partial" || result.Credibility() != "execution_incomplete" {
		t.Fatal("storage failure hidden")
	}
}
