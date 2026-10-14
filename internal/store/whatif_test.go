package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

func TestWhatifKeepsExecutionOrderSourceIdentityAndFinalization(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	seconds := "2"
	run := WhatifRun{Dataset: dataset, Input: "journal", ChainSHA: strings.Repeat("b", 64), SourceSHA: strings.Repeat("a", 64), HelperSHA: strings.Repeat("c", 64), Policy: whatif.Policy{Request: &seconds}}
	id, err := s.BeginWhatif(ctx, run, "private")
	if err != nil {
		t.Fatal(err)
	}
	source := &whatif.Source{Writer: "synthetic", Engine: "1", Step: "1", Ordinal: "3"}
	step := whatif.Step{Execution: "1", Mono: "0", Parent: "0", ArmExecution: "0", Source: source, Input: "start", Digest: "0x" + strings.Repeat("d", 64), Comparable: true, Counterfactual: true, Model: whatif.Model}
	if err = s.PutWhatifStep(ctx, id, step); err != nil {
		t.Fatal(err)
	}
	if err = s.PutWhatifStep(ctx, id, step); err == nil {
		t.Fatal("duplicate execution accepted")
	}
	step.Execution = "3"
	if err = s.PutWhatifStep(ctx, id, step); err == nil {
		t.Fatal("skipped execution accepted")
	}
	step.Execution = "2"
	step.Generated = true
	step.Source = nil
	step.Cause = source
	step.Parent = "1"
	step.Input = "backlog"
	step.Comparable = false
	if err = s.PutWhatifStep(ctx, id, step); err != nil {
		t.Fatal(err)
	}
	rows, err := s.WhatifResults(ctx, id, 1, 1)
	if err != nil || len(rows) != 1 || rows[0].Source != nil || rows[0].Execution != "2" {
		t.Fatal(rows, err)
	}
	summary := whatif.Summary{Model: whatif.Model, Status: "completed", BaselineValidated: true, TimerValidated: true, Horizon: "recorded_source_end", Scopes: []whatif.Scope{{Writer: "synthetic", Engine: "1", Execution: "2", Mono: "0"}}}
	if err = s.FinishWhatif(ctx, id, summary); err != nil {
		t.Fatal(err)
	}
	stored, err := s.WhatifRun(ctx, dataset, id)
	if err != nil || stored.Summary.Steps != 2 || stored.Summary.Generated != 1 || stored.Summary.SourceSteps != 1 || stored.Status != "completed" || stored.PolicySHA == "" {
		t.Fatal(stored, err)
	}
	if err = s.PutWhatifStep(ctx, id, step); !errors.Is(err, ErrWhatifState) {
		t.Fatal("finalized run changed", err)
	}
	if err = s.FinishWhatif(ctx, id, summary); !errors.Is(err, ErrWhatifState) {
		t.Fatal("finalized summary changed", err)
	}
	run.SourceSHA = strings.Repeat("e", 64)
	if _, err = s.BeginWhatif(ctx, run, "private"); err == nil {
		t.Fatal("different source linked")
	}
}
