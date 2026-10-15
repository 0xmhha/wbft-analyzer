package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/jackc/pgx/v5"
)

type ScenarioJob struct {
	ID           int64                  `json:"id"`
	Dataset      int64                  `json:"dataset_id"`
	Source       string                 `json:"source_id"`
	SourceSHA    string                 `json:"source_sha256"`
	ExecutionSHA string                 `json:"execution_sha256"`
	Change       scenario.NetworkChange `json:"change"`
	ChangeSHA    string                 `json:"change_sha256"`
	Status       string                 `json:"status"`
	Run          *int64                 `json:"scenario_id"`
	Issue        string                 `json:"issue,omitempty"`
	Created      time.Time              `json:"created_at"`
	Started      *time.Time             `json:"started_at"`
	Finished     *time.Time             `json:"finished_at"`
}

const scenarioJobColumns = `id,dataset_id,source_id,source_sha256,execution_sha256,change,change_sha256,status,scenario_id,issue,created_at,started_at,finished_at`

func scanScenarioJob(row pgx.Row) (ScenarioJob, error) {
	var j ScenarioJob
	var raw []byte
	err := row.Scan(&j.ID, &j.Dataset, &j.Source, &j.SourceSHA, &j.ExecutionSHA, &raw, &j.ChangeSHA, &j.Status, &j.Run, &j.Issue, &j.Created, &j.Started, &j.Finished)
	if err == nil {
		err = json.Unmarshal(raw, &j.Change)
	}
	return j, err
}
func (s *Store) EnqueueScenario(ctx context.Context, j ScenarioJob) (ScenarioJob, error) {
	var out ScenarioJob
	change, hash, err := j.Change.Canonical()
	if err != nil {
		return out, err
	}
	if j.Dataset < 1 || !logs.Identifier(j.Source) || !whatifSHA.MatchString(j.SourceSHA) || !whatifSHA.MatchString(j.ExecutionSHA) {
		return out, ErrScenarioState
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext(current_schema()),1463969364)`); err != nil {
			return err
		}
		var allowed, deleting bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock_shared(hashtextextended('wbft-analyzer:range:'||current_schema()||':'||$1::bigint::text,0)),EXISTS(SELECT 1 FROM dataset_deletions WHERE dataset_id=$1)`, j.Dataset).Scan(&allowed, &deleting); err != nil {
			return err
		}
		if !allowed {
			return ErrDatasetBusy
		}
		if deleting {
			return ErrDatasetDeleting
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM reexec_jobs WHERE status IN ('queued','running'))+(SELECT count(*) FROM whatif_jobs WHERE status IN ('queued','running'))+(SELECT count(*) FROM scenario_jobs WHERE status IN ('queued','running'))`).Scan(&count); err != nil {
			return err
		}
		if count >= MaxReexecJobs {
			return ErrReexecQueueFull
		}
		out, err = scanScenarioJob(tx.QueryRow(ctx, `INSERT INTO scenario_jobs(dataset_id,source_id,source_sha256,execution_sha256,change,change_sha256,status) VALUES($1,$2,$3,$4,$5,$6,'queued') RETURNING `+scenarioJobColumns, j.Dataset, j.Source, j.SourceSHA, j.ExecutionSHA, change, hash))
		return err
	})
	return out, err
}
func (s *Store) ScenarioJobs(ctx context.Context, dataset int64) ([]ScenarioJob, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scenarioJobColumns+` FROM scenario_jobs WHERE dataset_id=$1 ORDER BY id DESC LIMIT 100`, dataset)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.CollectableRow) (ScenarioJob, error) { return scanScenarioJob(r) })
}
func (s *Store) ScenarioJob(ctx context.Context, dataset, id int64) (ScenarioJob, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scenarioJobColumns+` FROM scenario_jobs WHERE dataset_id=$1 AND id=$2`, dataset, id)
	if err != nil {
		return ScenarioJob{}, err
	}
	return one(rows, func(r pgx.CollectableRow) (ScenarioJob, error) { return scanScenarioJob(r) })
}
func (s *Store) ClaimScenarioJob(ctx context.Context, owner string) (ScenarioJob, error) {
	if !logs.Identifier(owner) {
		return ScenarioJob{}, ErrScenarioState
	}
	var job ScenarioJob
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		candidate, err := scanScenarioJob(tx.QueryRow(ctx, `SELECT `+scenarioJobColumns+` FROM scenario_jobs WHERE status='queued' ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1`))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var available, deleting bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock_shared(hashtextextended('wbft-analyzer:range:'||current_schema()||':'||$1::bigint::text,0)),EXISTS(SELECT 1 FROM dataset_deletions WHERE dataset_id=$1)`, candidate.Dataset).Scan(&available, &deleting); err != nil {
			return err
		}
		if !available || deleting {
			return ErrNotFound
		}
		job, err = scanScenarioJob(tx.QueryRow(ctx, `UPDATE scenario_jobs SET status='running',owner=$2,started_at=now() WHERE id=$1 RETURNING `+scenarioJobColumns, candidate.ID, owner))
		return err
	})
	return job, err
}
func (s *Store) BeginScenarioJob(ctx context.Context, id int64, owner string, e scenario.Experiment) (int64, error) {
	var run int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		j, err := scanScenarioJob(tx.QueryRow(ctx, `SELECT `+scenarioJobColumns+` FROM scenario_jobs WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		var actualOwner string
		if err := tx.QueryRow(ctx, `SELECT owner FROM scenario_jobs WHERE id=$1`, id).Scan(&actualOwner); err != nil {
			return err
		}
		_, changeHash, err := e.Change.Canonical()
		if err != nil {
			return err
		}
		if actualOwner != owner || j.Status != "running" || j.Run != nil || j.Dataset != e.Provenance.Dataset || j.SourceSHA != e.SourceSHA256 || j.ExecutionSHA != e.ExecutionSHA256 || j.ChangeSHA != changeHash {
			return ErrScenarioState
		}
		run, err = beginScenario(ctx, tx, e)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE scenario_jobs SET scenario_id=$2 WHERE id=$1`, id, run)
		return err
	})
	return run, err
}
func (s *Store) FinishScenarioJob(ctx context.Context, id int64, owner, status, issue string) error {
	if status != "succeeded" && status != "failed" && status != "cancelled" || len(issue) > 128 {
		return ErrScenarioState
	}
	tag, err := s.pool.Exec(ctx, `UPDATE scenario_jobs SET status=$3,issue=$4,finished_at=now() WHERE id=$1 AND owner=$2 AND status='running' AND ($3!='succeeded' OR EXISTS(SELECT 1 FROM scenario_runs r WHERE r.id=scenario_jobs.scenario_id AND r.status='completed' AND r.finished_at IS NOT NULL))`, id, owner, status, issue)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrScenarioState
	}
	return err
}

// RecoverScenarioJobs requires the shared replay worker lease. Seed prefixes
// survive interruption; only an already finalised complete run is a success.
func (s *Store) RecoverScenarioJobs(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT `+scenarioJobColumns+` FROM scenario_jobs WHERE status='running' ORDER BY id`)
	if err != nil {
		return err
	}
	jobs, err := collect(rows, func(r pgx.CollectableRow) (ScenarioJob, error) { return scanScenarioJob(r) })
	if err != nil {
		return err
	}
	for _, j := range jobs {
		status, issue := "failed", "worker_interrupted"
		if j.Run != nil {
			run, err := s.ScenarioRun(ctx, j.Dataset, *j.Run)
			if err != nil {
				return err
			}
			switch run.Status {
			case "running":
				run.Status = "partial"
				if err := s.FinishScenario(ctx, *j.Run, run); err != nil {
					return err
				}
			case "completed":
				status, issue = "succeeded", ""
			}
		}
		tag, err := s.pool.Exec(ctx, `UPDATE scenario_jobs SET status=$2,issue=$3,finished_at=now() WHERE id=$1 AND status='running'`, j.ID, status, issue)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrScenarioState
		}
	}
	return nil
}
