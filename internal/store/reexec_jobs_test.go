package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/jackc/pgx/v5/pgxpool"
)

func jobDataset(t *testing.T, s *Store) int64 {
	t.Helper()
	ctx := context.Background()
	d, release, err := s.BeginMessages(ctx, NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-jobs", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = s.PutMessageInput(ctx, d.ID, messages.Summary{ID: "journal", Kind: "journal", Node: "node", SHA256: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	return d.ID
}
func testJob(dataset int64) ReexecJob {
	return ReexecJob{Dataset: dataset, Input: "journal", Source: "source", SourceSHA: strings.Repeat("b", 64), From: "1", To: "2", Mode: "closed"}
}

func TestReexecQueueConcurrentBoundAndScope(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d := jobDataset(t, s)
	cfg := s.pool.Config()
	cfg.MaxConns = 1
	s.pool.Close()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.pool = pool
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for range 48 {
		wg.Go(func() {
			_, err := s.EnqueueReexec(ctx, testJob(d))
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrReexecQueueFull) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	jobs, err := s.ReexecJobs(ctx, d)
	if err != nil || accepted.Load() != MaxReexecJobs || len(jobs) != MaxReexecJobs {
		t.Fatal(accepted.Load(), len(jobs), err)
	}
	if _, err = s.ReexecJob(ctx, d+100, jobs[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-dataset job exposed", err)
	}
	lease, err := s.ReexecWorkerLease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close(ctx)
	if other, err := s.ReexecWorkerLease(ctx); !errors.Is(err, ErrReexecWorkerBusy) {
		if other != nil {
			other.Close(ctx)
		}
		t.Fatal("duplicate worker", err)
	}
	job, err := s.ClaimReexecJob(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishReexecJob(ctx, job.ID, "other", "failed", "x"); !errors.Is(err, ErrReexecJobState) {
		t.Fatal("wrong owner accepted", err)
	}
	if err = s.FinishReexecJob(ctx, job.ID, "owner", "succeeded", ""); !errors.Is(err, ErrReexecJobState) {
		t.Fatal("success without finalised result", err)
	}
	if err = s.FinishReexecJob(ctx, job.ID, "owner", "failed", "source_changed"); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishReexecJob(ctx, job.ID, "owner", "failed", "mutated"); !errors.Is(err, ErrReexecJobState) {
		t.Fatal("terminal mutation", err)
	}
	if _, err = s.EnqueueReexec(ctx, testJob(d)); err != nil {
		t.Fatal("queue capacity not released", err)
	}
}

func TestReexecJobRecoveryAndMatchingResult(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d := jobDataset(t, s)
	create := func() ReexecJob {
		t.Helper()
		if _, err := s.EnqueueReexec(ctx, testJob(d)); err != nil {
			t.Fatal(err)
		}
		j, err := s.ClaimReexecJob(ctx, "owner")
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	run := func(mode string) int64 {
		t.Helper()
		id, err := s.BeginReexec(ctx, d, "journal", "1", "2", "private-chain", reexec.Result{Mode: mode, Version: reexec.Version, Status: "running"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b, c := create(), create(), create()
	wrong := run("counterfactual")
	if err := s.LinkReexecJob(ctx, a.ID, "owner", wrong); !errors.Is(err, ErrReexecJobState) {
		t.Fatal("mode mismatch linked", err)
	}
	running, finished := run("closed"), run("closed")
	if err := s.LinkReexecJob(ctx, b.ID, "owner", running); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkReexecJob(ctx, c.ID, "owner", finished); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishReexecJob(ctx, c.ID, "owner", "succeeded", ""); !errors.Is(err, ErrReexecJobState) {
		t.Fatal("unfinished result accepted", err)
	}
	if err := s.FinishReexec(ctx, finished, reexec.Result{Mode: "closed", Status: "partial"}); err != nil {
		t.Fatal(err)
	}
	lease, err := s.ReexecWorkerLease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close(ctx)
	if err = s.RecoverReexecJobs(ctx); err != nil {
		t.Fatal(err)
	}
	for _, j := range []ReexecJob{a, b} {
		got, e := s.ReexecJob(ctx, d, j.ID)
		if e != nil || got.Status != "failed" || got.Issue != "worker_interrupted" {
			t.Fatal(got, e)
		}
	}
	got, err := s.ReexecJob(ctx, d, c.ID)
	if err != nil || got.Status != "succeeded" {
		t.Fatal(got, err)
	}
	r, err := s.ReexecRun(ctx, d, running)
	if err != nil || r.Status != "failed" || r.Summary.Issue != "worker_interrupted" {
		t.Fatal(r, err)
	}
}
