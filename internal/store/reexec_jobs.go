package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const MaxReexecJobs = 32

var ErrReexecQueueFull = errors.New("replay queue is full")
var ErrReexecWorkerBusy = errors.New("replay worker is already active")
var ErrReexecJobState = errors.New("replay job is not owned or already finished")

type ReexecJob struct {
	ID        int64      `json:"id"`
	Dataset   int64      `json:"dataset_id"`
	Input     string     `json:"input_id"`
	Source    string     `json:"source_id"`
	SourceSHA string     `json:"source_sha256"`
	From      string     `json:"from_height"`
	To        string     `json:"to_height"`
	Mode      string     `json:"mode"`
	Status    string     `json:"status"`
	Run       *int64     `json:"reexec_id"`
	Issue     string     `json:"issue,omitempty"`
	Created   time.Time  `json:"created_at"`
	Started   *time.Time `json:"started_at"`
	Finished  *time.Time `json:"finished_at"`
}

const jobColumns = `id,dataset_id,input_id,source_id,source_sha256,from_height::text,to_height::text,mode,status,reexec_id,issue,created_at,started_at,finished_at`

func scanJob(r pgx.Row) (ReexecJob, error) {
	var j ReexecJob
	err := r.Scan(&j.ID, &j.Dataset, &j.Input, &j.Source, &j.SourceSHA, &j.From, &j.To, &j.Mode, &j.Status, &j.Run, &j.Issue, &j.Created, &j.Started, &j.Finished)
	return j, err
}
func (s *Store) EnqueueReexec(ctx context.Context, j ReexecJob) (ReexecJob, error) {
	var out ReexecJob
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext(current_schema()),1463969364)`); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM reexec_jobs WHERE status IN ('queued','running')`).Scan(&count); err != nil {
			return err
		}
		if count >= MaxReexecJobs {
			return ErrReexecQueueFull
		}
		row, err := scanJob(tx.QueryRow(ctx, `INSERT INTO reexec_jobs(dataset_id,input_id,source_id,source_sha256,from_height,to_height,mode,status) VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7,'queued') RETURNING `+jobColumns, j.Dataset, j.Input, j.Source, j.SourceSHA, j.From, j.To, j.Mode))
		out = row
		return err
	})
	return out, err
}
func (s *Store) ReexecJobs(ctx context.Context, dataset int64) ([]ReexecJob, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+jobColumns+` FROM reexec_jobs WHERE dataset_id=$1 ORDER BY id DESC LIMIT 100`, dataset)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.CollectableRow) (ReexecJob, error) { return scanJob(r) })
}
func (s *Store) ReexecJob(ctx context.Context, dataset, id int64) (ReexecJob, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+jobColumns+` FROM reexec_jobs WHERE dataset_id=$1 AND id=$2`, dataset, id)
	if err != nil {
		return ReexecJob{}, err
	}
	return one(rows, func(r pgx.CollectableRow) (ReexecJob, error) { return scanJob(r) })
}
func (s *Store) ClaimReexecJob(ctx context.Context, owner string) (ReexecJob, error) {
	row := s.pool.QueryRow(ctx, `UPDATE reexec_jobs SET status='running',owner=$1,started_at=now() WHERE id=(SELECT id FROM reexec_jobs WHERE status='queued' ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING `+jobColumns, owner)
	j, err := scanJob(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return j, ErrNotFound
	}
	return j, err
}
func (s *Store) LinkReexecJob(ctx context.Context, id int64, owner string, run int64) error {
	tag, err := s.pool.Exec(ctx, `UPDATE reexec_jobs j SET reexec_id=$3 WHERE j.id=$1 AND j.owner=$2 AND j.status='running' AND j.reexec_id IS NULL AND EXISTS(SELECT 1 FROM reexec_runs r WHERE r.id=$3 AND r.dataset_id=j.dataset_id AND r.input_id=j.input_id AND r.from_height=j.from_height AND r.to_height=j.to_height AND r.summary->>'mode'=j.mode AND r.status='running')`, id, owner, run)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrReexecJobState
	}
	return err
}
func (s *Store) FinishReexecJob(ctx context.Context, id int64, owner, status, issue string) error {
	if status != "succeeded" && status != "failed" && status != "cancelled" {
		return ErrReexecJobState
	}
	tag, err := s.pool.Exec(ctx, `UPDATE reexec_jobs SET status=$3,issue=$4,finished_at=now() WHERE id=$1 AND owner=$2 AND status='running' AND ($3!='succeeded' OR EXISTS(SELECT 1 FROM reexec_runs r WHERE r.id=reexec_jobs.reexec_id AND r.finished_at IS NOT NULL AND r.status NOT IN ('running','failed')))`, id, owner, status, issue)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrReexecJobState
	}
	return err
}

// ReexecWorkerLease is a separate connection so a one-connection pool works.
func (s *Store) ReexecWorkerLease(ctx context.Context) (*pgx.Conn, error) {
	conn, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		return nil, err
	}
	var locked bool
	err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext(current_schema()),1463969365)`).Scan(&locked)
	if err != nil || !locked {
		_ = conn.Close(context.Background())
		if err != nil {
			return nil, err
		}
		return nil, ErrReexecWorkerBusy
	}
	return conn, nil
}

// RecoverReexecJobs is called only while holding the worker lease.
func (s *Store) RecoverReexecJobs(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT `+jobColumns+` FROM reexec_jobs WHERE status='running' ORDER BY id`)
	if err != nil {
		return err
	}
	jobs, err := collect(rows, func(r pgx.CollectableRow) (ReexecJob, error) { return scanJob(r) })
	if err != nil {
		return err
	}
	for _, job := range jobs {
		status, issue := "failed", "worker_interrupted"
		if job.Run != nil {
			run, err := s.ReexecRun(ctx, job.Dataset, *job.Run)
			if err != nil {
				return err
			}
			if run.Status == "running" {
				run.Summary.Status = "failed"
				run.Summary.Issue = issue
				if err = s.FinishReexec(ctx, run.ID, run.Summary); err != nil {
					return err
				}
			} else if run.Status != "failed" {
				status, issue = "succeeded", ""
			}
		}
		tag, err := s.pool.Exec(ctx, `UPDATE reexec_jobs SET status=$2,issue=$3,finished_at=now() WHERE id=$1 AND status='running'`, job.ID, status, issue)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrReexecJobState
		}
	}
	return nil
}
