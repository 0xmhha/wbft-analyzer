package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

func testWhatifJob(dataset int64) WhatifJob {
	seconds := "2"
	return WhatifJob{Dataset: dataset, Input: "journal", Source: "registered", SourceSHA: strings.Repeat("f", 64), InputSHA: strings.Repeat("a", 64), ChainSHA: strings.Repeat("b", 64), HelperSHA: strings.Repeat("c", 64), Policy: whatif.Policy{Request: &seconds}}
}
func TestWhatifQueueHashesOwnershipAndInterruptedRecovery(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	spec := testWhatifJob(dataset)
	job, err := s.EnqueueWhatif(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	job, err = s.ClaimWhatifJob(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	begin := func(chain string, policy whatif.Policy) int64 {
		t.Helper()
		id, err := s.BeginWhatif(ctx, WhatifRun{Dataset: dataset, Input: "journal", SourceSHA: spec.InputSHA, ChainSHA: chain, HelperSHA: spec.HelperSHA, Policy: policy, Summary: whatif.Summary{Model: whatif.Model, BaselineValidated: true}}, "private")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	wrong := begin(strings.Repeat("d", 64), spec.Policy)
	if err = s.LinkWhatifJob(ctx, job.ID, "owner", wrong); !errors.Is(err, ErrReexecJobState) {
		t.Fatal("different chain linked", err)
	}
	run := begin(spec.ChainSHA, spec.Policy)
	if err = s.LinkWhatifJob(ctx, job.ID, "other", run); !errors.Is(err, ErrReexecJobState) {
		t.Fatal("foreign owner linked", err)
	}
	if err = s.LinkWhatifJob(ctx, job.ID, "owner", run); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishWhatifJob(ctx, job.ID, "owner", "succeeded", ""); !errors.Is(err, ErrReexecJobState) {
		t.Fatal("unfinished experiment promoted", err)
	}
	queued, err := s.EnqueueWhatif(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := s.ReexecWorkerLease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Close(ctx) }()
	if err = s.RecoverWhatifJobs(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.WhatifJob(ctx, dataset, job.ID)
	if err != nil || recovered.Status != "failed" || recovered.Issue != "worker_interrupted" {
		t.Fatal(recovered, err)
	}
	result, err := s.WhatifRun(ctx, dataset, run)
	if err != nil || result.Status != "partial" {
		t.Fatal(result, err)
	}
	retained, err := s.WhatifJob(ctx, dataset, queued.ID)
	if err != nil || retained.Status != "queued" {
		t.Fatal(retained, err)
	}
}
func TestWhatifQueueSharesGlobalBoundWithReexec(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	for i := 0; i < MaxReexecJobs; i++ {
		if i%2 == 0 {
			if _, err := s.EnqueueWhatif(ctx, testWhatifJob(dataset)); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := s.EnqueueReexec(ctx, testJob(dataset)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := s.EnqueueWhatif(ctx, testWhatifJob(dataset)); !errors.Is(err, ErrReexecQueueFull) {
		t.Fatal("timer queue bound exceeded", err)
	}
	if _, err := s.EnqueueReexec(ctx, testJob(dataset)); !errors.Is(err, ErrReexecQueueFull) {
		t.Fatal("replay queue bound exceeded", err)
	}
}
