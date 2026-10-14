package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/whatif"
	"github.com/jackc/pgx/v5"
)

type WhatifJob struct {
	InputSHA  string        `json:"input_sha256"`
	ChainSHA  string        `json:"chain_sha256"`
	HelperSHA string        `json:"helper_sha256"`
	ID        int64         `json:"id"`
	Dataset   int64         `json:"dataset_id"`
	Input     string        `json:"input_id"`
	Source    string        `json:"source_id"`
	SourceSHA string        `json:"source_sha256"`
	Policy    whatif.Policy `json:"timer_policy"`
	PolicySHA string        `json:"policy_sha256"`
	Status    string        `json:"status"`
	Run       *int64        `json:"whatif_id"`
	Issue     string        `json:"issue,omitempty"`
	Created   time.Time     `json:"created_at"`
	Started   *time.Time    `json:"started_at"`
	Finished  *time.Time    `json:"finished_at"`
}

const whatifJobColumns = `id,dataset_id,input_id,source_id,source_sha256,input_sha256,chain_sha256,helper_sha256,policy,policy_sha256,status,whatif_id,issue,created_at,started_at,finished_at`

func scanWhatifJob(row pgx.Row) (WhatifJob, error) {
	var job WhatifJob
	var raw []byte
	err := row.Scan(&job.ID, &job.Dataset, &job.Input, &job.Source, &job.SourceSHA, &job.InputSHA, &job.ChainSHA, &job.HelperSHA, &raw, &job.PolicySHA, &job.Status, &job.Run, &job.Issue, &job.Created, &job.Started, &job.Finished)
	if err == nil {
		err = json.Unmarshal(raw, &job.Policy)
	}
	return job, err
}
func (s *Store) EnqueueWhatif(ctx context.Context, job WhatifJob) (WhatifJob, error) {
	var out WhatifJob
	policy, hash, err := job.Policy.Canonical()
	if err != nil {
		return out, err
	}
	if !whatifSHA.MatchString(job.SourceSHA) || !whatifSHA.MatchString(job.InputSHA) || !whatifSHA.MatchString(job.ChainSHA) || !whatifSHA.MatchString(job.HelperSHA) {
		return out, whatif.ErrEvidence
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext(current_schema()),1463969364)`); err != nil {
			return err
		}
		var allowed, deleting bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock_shared(hashtextextended('wbft-analyzer:range:'||current_schema()||':'||$1::bigint::text,0)),EXISTS(SELECT 1 FROM dataset_deletions WHERE dataset_id=$1)`, job.Dataset).Scan(&allowed, &deleting); err != nil {
			return err
		}
		if !allowed {
			return ErrDatasetBusy
		}
		if deleting {
			return ErrDatasetDeleting
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM reexec_jobs WHERE status IN ('queued','running'))+(SELECT count(*) FROM whatif_jobs WHERE status IN ('queued','running'))`).Scan(&count); err != nil {
			return err
		}
		if count >= MaxReexecJobs {
			return ErrReexecQueueFull
		}
		row, err := scanWhatifJob(tx.QueryRow(ctx, `INSERT INTO whatif_jobs(dataset_id,input_id,source_id,source_sha256,input_sha256,chain_sha256,helper_sha256,policy,policy_sha256,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'queued') RETURNING `+whatifJobColumns, job.Dataset, job.Input, job.Source, job.SourceSHA, job.InputSHA, job.ChainSHA, job.HelperSHA, policy, hash))
		out = row
		return err
	})
	return out, err
}
func (s *Store) WhatifJobs(ctx context.Context, dataset int64) ([]WhatifJob, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+whatifJobColumns+` FROM whatif_jobs WHERE dataset_id=$1 ORDER BY id DESC LIMIT 100`, dataset)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(row pgx.CollectableRow) (WhatifJob, error) { return scanWhatifJob(row) })
}
func (s *Store) WhatifJob(ctx context.Context, dataset, id int64) (WhatifJob, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+whatifJobColumns+` FROM whatif_jobs WHERE dataset_id=$1 AND id=$2`, dataset, id)
	if err != nil {
		return WhatifJob{}, err
	}
	return one(rows, func(row pgx.CollectableRow) (WhatifJob, error) { return scanWhatifJob(row) })
}
func (s *Store) ClaimWhatifJob(ctx context.Context, owner string) (WhatifJob, error) {
	job, err := scanWhatifJob(s.pool.QueryRow(ctx, `UPDATE whatif_jobs SET status='running',owner=$1,started_at=now() WHERE id=(SELECT id FROM whatif_jobs WHERE status='queued' ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING `+whatifJobColumns, owner))
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return job, err
}
func (s *Store) LinkWhatifJob(ctx context.Context, id int64, owner string, run int64) error {
	tag, err := s.pool.Exec(ctx, `UPDATE whatif_jobs j SET whatif_id=$3 WHERE j.id=$1 AND j.owner=$2 AND j.status='running' AND j.whatif_id IS NULL AND EXISTS(SELECT 1 FROM whatif_runs r WHERE r.id=$3 AND r.dataset_id=j.dataset_id AND r.input_id=j.input_id AND r.source_sha256=j.input_sha256 AND r.chain_sha256=j.chain_sha256 AND r.helper_sha256=j.helper_sha256 AND r.policy_sha256=j.policy_sha256 AND r.policy=j.policy AND r.status='running')`, id, owner, run)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrReexecJobState
	}
	return err
}
func (s *Store) FinishWhatifJob(ctx context.Context, id int64, owner, status, issue string) error {
	if status != "succeeded" && status != "failed" && status != "cancelled" {
		return ErrReexecJobState
	}
	tag, err := s.pool.Exec(ctx, `UPDATE whatif_jobs SET status=$3,issue=$4,finished_at=now() WHERE id=$1 AND owner=$2 AND status='running' AND ($3!='succeeded' OR EXISTS(SELECT 1 FROM whatif_runs r WHERE r.id=whatif_jobs.whatif_id AND r.finished_at IS NOT NULL AND r.status='completed'))`, id, owner, status, issue)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrReexecJobState
	}
	return err
}

// RecoverWhatifJobs requires the shared replay-worker lease. Queued work is
// retained, and an interrupted partial execution can never become success.
func (s *Store) RecoverWhatifJobs(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT `+whatifJobColumns+` FROM whatif_jobs WHERE status='running' ORDER BY id`)
	if err != nil {
		return err
	}
	jobs, err := collect(rows, func(row pgx.CollectableRow) (WhatifJob, error) { return scanWhatifJob(row) })
	if err != nil {
		return err
	}
	for _, job := range jobs {
		status, issue := "failed", "worker_interrupted"
		if job.Run != nil {
			run, err := s.WhatifRun(ctx, job.Dataset, *job.Run)
			if err != nil {
				return err
			}
			switch run.Status {
			case "running":
				run.Summary.Status = "partial"
				run.Summary.Issue = issue
				if err = s.FinishWhatif(ctx, run.ID, run.Summary); err != nil {
					return err
				}
			case "completed":
				status, issue = "succeeded", ""
			}
		}
		tag, err := s.pool.Exec(ctx, `UPDATE whatif_jobs SET status=$2,issue=$3,finished_at=now() WHERE id=$1 AND status='running'`, job.ID, status, issue)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrReexecJobState
		}
	}
	return nil
}

// BeginWhatifJob creates and links a run under one job lock. A crash between
// creation and execution cannot leave an unowned running experiment.
func (s *Store) BeginWhatifJob(ctx context.Context, id int64, owner string, run WhatifRun, chain string) (int64, error) {
	var out int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var actualOwner, status string
		var linked *int64
		job, err := scanWhatifJob(tx.QueryRow(ctx, `SELECT `+whatifJobColumns+` FROM whatif_jobs WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if err = tx.QueryRow(ctx, `SELECT owner FROM whatif_jobs WHERE id=$1`, id).Scan(&actualOwner); err != nil {
			return err
		}
		status, linked = job.Status, job.Run
		_, policyHash, err := run.Policy.Canonical()
		if err != nil {
			return err
		}
		if actualOwner != owner || status != "running" || linked != nil || job.Dataset != run.Dataset || job.Input != run.Input || job.InputSHA != run.SourceSHA || job.ChainSHA != run.ChainSHA || job.HelperSHA != run.HelperSHA || job.PolicySHA != policyHash {
			return ErrReexecJobState
		}
		out, err = beginWhatif(ctx, tx, run, chain)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE whatif_jobs SET whatif_id=$2 WHERE id=$1`, id, out)
		return err
	})
	return out, err
}
