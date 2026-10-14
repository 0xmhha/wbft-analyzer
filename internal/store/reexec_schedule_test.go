package store

import (
	"context"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"testing"
)

func TestScheduleJobRetainsExactSpecificationAndRefusesDifferentRun(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	d := jobDataset(t, s)
	j := testJob(d)
	j.AnswerScope = "context"
	j.WarmupHeights = 0
	j.Schedule = &reexec.InputSchedule{Action: "drop", Writer: "synthetic", Engine: "18446744073709551615", Step: "2"}
	stored, e := s.EnqueueReexec(ctx, j)
	if e != nil || stored.Schedule == nil || *stored.Schedule != *j.Schedule {
		t.Fatal(stored, e)
	}
	job, e := s.ClaimReexecJob(ctx, "owner")
	if e != nil || job.Schedule == nil || *job.Schedule != *j.Schedule {
		t.Fatal(job, e)
	}
	run := func(schedule *reexec.InputSchedule) int64 {
		t.Helper()
		id, e := s.BeginReexec(ctx, d, "journal", "1", "2", "private", reexec.Result{Mode: "counterfactual", AnswerScope: "context", WarmupHeights: 0, Schedule: schedule})
		if e != nil {
			t.Fatal(e)
		}
		return id
	}
	other := *j.Schedule
	other.Step = "3"
	if e = s.LinkReexecJob(ctx, job.ID, "owner", run(&other)); !errors.Is(e, ErrReexecJobState) {
		t.Fatal("different experiment linked", e)
	}
	if e = s.LinkReexecJob(ctx, job.ID, "owner", run(j.Schedule)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []ReexecJob{func() ReexecJob { x := j; x.WarmupHeights = 2; return x }(), func() ReexecJob { x := j; x.AnswerScope = "step"; return x }(), func() ReexecJob { x := j; x.Mode = "counterfactual"; return x }()} {
		if _, e = s.EnqueueReexec(ctx, bad); e == nil {
			t.Fatal("conflicting policy stored")
		}
	}
}
