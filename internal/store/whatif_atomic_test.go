package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

func TestWhatifJobStartAtomicallyLinksOnlyPinnedRun(t *testing.T) {
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
	run := WhatifRun{Dataset: dataset, Input: spec.Input, SourceSHA: spec.InputSHA, ChainSHA: spec.ChainSHA, HelperSHA: spec.HelperSHA, Policy: spec.Policy, Summary: whatif.Summary{Model: whatif.Model}}
	wrong := run
	wrong.HelperSHA = strings.Repeat("d", 64)
	if _, err = s.BeginWhatifJob(ctx, job.ID, "owner", wrong, "private"); !errors.Is(err, ErrReexecJobState) {
		t.Fatal("different helper linked", err)
	}
	rows, err := s.WhatifRuns(ctx, dataset)
	if err != nil || len(rows) != 0 {
		t.Fatal("rejected start left an orphan", rows, err)
	}
	id, err := s.BeginWhatifJob(ctx, job.ID, "owner", run, "private")
	if err != nil {
		t.Fatal(err)
	}
	linked, err := s.WhatifJob(ctx, dataset, job.ID)
	if err != nil || linked.Run == nil || *linked.Run != id {
		t.Fatal(linked, err)
	}
	if _, err = s.BeginWhatifJob(ctx, job.ID, "owner", run, "private"); !errors.Is(err, ErrReexecJobState) {
		t.Fatal("job started twice", err)
	}
	rows, err = s.WhatifRuns(ctx, dataset)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
}
