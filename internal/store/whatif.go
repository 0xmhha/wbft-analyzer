package store

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/whatif"
	"github.com/jackc/pgx/v5"
)

var ErrWhatifState = errors.New("timer experiment is already finalised or out of order")
var whatifSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

type WhatifRun struct {
	ID        int64          `json:"id"`
	Dataset   int64          `json:"dataset_id"`
	Input     string         `json:"input_id"`
	ChainSHA  string         `json:"chain_sha256"`
	SourceSHA string         `json:"source_sha256"`
	HelperSHA string         `json:"helper_sha256"`
	Policy    whatif.Policy  `json:"timer_policy"`
	PolicySHA string         `json:"policy_sha256"`
	Created   time.Time      `json:"created_at"`
	Finished  *time.Time     `json:"finished_at"`
	Status    string         `json:"status"`
	Summary   whatif.Summary `json:"summary"`
}

type whatifBeginner interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Store) BeginWhatif(ctx context.Context, run WhatifRun, chain string) (int64, error) {
	return beginWhatif(ctx, s.pool, run, chain)
}
func beginWhatif(ctx context.Context, q whatifBeginner, run WhatifRun, chain string) (int64, error) {
	policy, hash, err := run.Policy.Canonical()
	if err != nil {
		return 0, err
	}
	if run.Dataset < 1 || !whatifSHA.MatchString(run.ChainSHA) || !whatifSHA.MatchString(run.SourceSHA) || !whatifSHA.MatchString(run.HelperSHA) || chain == "" {
		return 0, whatif.ErrEvidence
	}
	summary := run.Summary
	if summary.Scopes == nil {
		summary.Scopes = []whatif.Scope{}
	}
	if summary.SourceVersions == nil {
		summary.SourceVersions = []string{}
	}
	summary.Status = "running"
	summary.Model = whatif.Model
	summary.Version = whatif.Version
	raw, err := json.Marshal(summary)
	if err != nil {
		return 0, err
	}
	var id int64
	err = q.QueryRow(ctx, `INSERT INTO whatif_runs(dataset_id,input_id,chain_path,chain_sha256,source_sha256,helper_sha256,policy,policy_sha256,execution_model,status,summary) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,'running',$10 WHERE EXISTS(SELECT 1 FROM message_inputs WHERE dataset_id=$1 AND input_id=$2 AND summary->>'sha256'=$5) RETURNING id`, run.Dataset, run.Input, chain, run.ChainSHA, run.SourceSHA, run.HelperSHA, policy, hash, whatif.Model, raw).Scan(&id)
	return id, err
}
func (s *Store) PutWhatifStep(ctx context.Context, id int64, step whatif.Step) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM whatif_runs WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
			return err
		}
		if status != "running" {
			return ErrWhatifState
		}
		var previous uint64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(execution_step),0) FROM whatif_results WHERE run_id=$1`, id).Scan(&previous); err != nil {
			return err
		}
		if err := step.Validate(previous); err != nil {
			return err
		}
		if step.Answers == nil {
			step.Answers = []whatif.Answer{}
		}
		if step.Questions == nil {
			step.Questions = []whatif.Question{}
		}
		raw, err := json.Marshal(step)
		if err != nil {
			return err
		}
		n, _ := strconv.ParseInt(step.Execution, 10, 64)
		mono, _ := strconv.ParseInt(step.Mono, 10, 64)
		_, err = tx.Exec(ctx, `INSERT INTO whatif_results(run_id,execution_step,height,round,t_mono_ns,generated,record) VALUES($1,$2,$3::numeric,$4::numeric,$5,$6,$7)`, id, n, step.State.Height, step.State.Round, mono, step.Generated, raw)
		return err
	})
}
func (s *Store) FinishWhatif(ctx context.Context, id int64, result whatif.Summary) error {
	if result.Status != "completed" && result.Status != "partial" && result.Status != "failed" || result.FutureTail || result.Model != whatif.Model {
		return whatif.ErrEvidence
	}
	if result.Status == "completed" && (!result.BaselineValidated || !result.TimerValidated || len(result.Scopes) == 0 || result.Horizon != "recorded_source_end") {
		return whatif.ErrEvidence
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM whatif_runs WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
			return err
		}
		if status != "running" {
			return ErrWhatifState
		}
		if err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE generated),count(*) FILTER(WHERE NOT generated) FROM whatif_results WHERE run_id=$1`, id).Scan(&result.Steps, &result.Generated, &result.SourceSteps); err != nil {
			return err
		}
		if result.Status == "completed" && result.Steps == 0 {
			return whatif.ErrEvidence
		}
		result.Version = whatif.Version
		if result.Scopes == nil {
			result.Scopes = []whatif.Scope{}
		}
		if result.SourceVersions == nil {
			result.SourceVersions = []string{}
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE whatif_runs SET status=$2,summary=$3,finished_at=now() WHERE id=$1`, id, result.Status, raw)
		return err
	})
}

const whatifColumns = `id,dataset_id,input_id,chain_sha256,source_sha256,helper_sha256,policy,policy_sha256,created_at,finished_at,status,summary`

func scanWhatif(row pgx.CollectableRow) (WhatifRun, error) {
	var run WhatifRun
	var policy, summary []byte
	err := row.Scan(&run.ID, &run.Dataset, &run.Input, &run.ChainSHA, &run.SourceSHA, &run.HelperSHA, &policy, &run.PolicySHA, &run.Created, &run.Finished, &run.Status, &summary)
	if err == nil {
		err = json.Unmarshal(policy, &run.Policy)
	}
	if err == nil {
		err = json.Unmarshal(summary, &run.Summary)
	}
	return run, err
}
func (s *Store) WhatifRun(ctx context.Context, dataset, id int64) (WhatifRun, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+whatifColumns+` FROM whatif_runs WHERE dataset_id=$1 AND id=$2`, dataset, id)
	if err != nil {
		return WhatifRun{}, err
	}
	return one(rows, scanWhatif)
}
func (s *Store) WhatifRuns(ctx context.Context, dataset int64) ([]WhatifRun, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+whatifColumns+` FROM whatif_runs WHERE dataset_id=$1 ORDER BY id DESC LIMIT 100`, dataset)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanWhatif)
}
func (s *Store) WhatifResults(ctx context.Context, id, after int64, limit int) ([]whatif.Step, error) {
	if after < 0 || limit < 1 || limit > 1000 {
		return nil, whatif.ErrEvidence
	}
	rows, err := s.pool.Query(ctx, `SELECT record FROM whatif_results WHERE run_id=$1 AND execution_step>$2 ORDER BY execution_step LIMIT $3`, id, after, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(row pgx.CollectableRow) (whatif.Step, error) {
		var step whatif.Step
		var raw []byte
		err := row.Scan(&raw)
		if err == nil {
			err = json.Unmarshal(raw, &step)
		}
		return step, err
	})
}
