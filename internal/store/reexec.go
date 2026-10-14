package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/jackc/pgx/v5"
)

var ErrReexecFinished = errors.New("closed replay is already finalised")

type ReexecRun struct {
	ID       int64         `json:"id"`
	Dataset  int64         `json:"dataset_id"`
	Input    string        `json:"input_id"`
	From     string        `json:"from_height"`
	To       string        `json:"to_height"`
	Created  time.Time     `json:"created_at"`
	Finished *time.Time    `json:"finished_at"`
	Status   string        `json:"status"`
	Summary  reexec.Result `json:"summary"`
}

func (s *Store) BeginReexec(ctx context.Context, dataset int64, input, from, to, chain string, summary reexec.Result) (int64, error) {
	summary.Status = "running"
	raw, err := json.Marshal(summary)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.pool.QueryRow(ctx, `INSERT INTO reexec_runs(dataset_id,input_id,from_height,to_height,chain_path,status,summary) VALUES($1,$2,$3::numeric,$4::numeric,$5,'running',$6) RETURNING id`, dataset, input, from, to, chain, raw).Scan(&id)
	return id, err
}
func (s *Store) PutReexecStep(ctx context.Context, id int64, step reexec.Step) error {
	raw, err := json.Marshal(step)
	if err != nil {
		return err
	}
	height := step.Height
	if step.ExecutionHeight != "" {
		height = step.ExecutionHeight
	}
	tag, err := s.pool.Exec(ctx, `WITH writable AS (SELECT id FROM reexec_runs WHERE id=$1 AND status='running' FOR UPDATE) INSERT INTO reexec_steps(run_id,ordinal,height,class,record,execution_ordinal) SELECT id,$2,$3::numeric,$4,$5,$6 FROM writable`, id, step.Ordinal, height, step.Class, raw, step.Cursor())
	if err == nil && tag.RowsAffected() != 1 {
		return ErrReexecFinished
	}
	return err
}
func (s *Store) FinishReexec(ctx context.Context, id int64, result reexec.Result) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT status FROM reexec_runs WHERE id=$1 FOR UPDATE`, id).Scan(&state); err != nil {
			return err
		}
		if state != "running" {
			return ErrReexecFinished
		}
		if err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE class='match'),count(*) FILTER(WHERE class IN ('output_diverged','env_mismatch','env_exhausted')),count(*) FILTER(WHERE class IN ('not_comparable','input_gap')),count(*) FILTER(WHERE class='warmup_suspect'),(array_agg(ordinal ORDER BY execution_ordinal) FILTER(WHERE class IN ('output_diverged','env_mismatch','env_exhausted')))[1],min(execution_ordinal) FILTER(WHERE class IN ('output_diverged','env_mismatch','env_exhausted')) FROM reexec_steps WHERE run_id=$1`, id).Scan(&result.Total, &result.Matches, &result.Mismatches, &result.NotComparable, &result.WarmupSuspect, &result.FirstMismatch, &result.FirstMismatchExecution); err != nil {
			return err
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE reexec_runs SET status=$2,summary=$3,finished_at=now() WHERE id=$1`, id, result.Status, raw)
		return err
	})
}

const reexecColumns = `id,dataset_id,input_id,from_height::text,to_height::text,created_at,finished_at,status,summary`

func scanReexec(r pgx.CollectableRow) (ReexecRun, error) {
	var x ReexecRun
	var raw []byte
	err := r.Scan(&x.ID, &x.Dataset, &x.Input, &x.From, &x.To, &x.Created, &x.Finished, &x.Status, &raw)
	if err == nil {
		err = json.Unmarshal(raw, &x.Summary)
	}
	return x, err
}
func (s *Store) ReexecRuns(ctx context.Context, dataset int64) ([]ReexecRun, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+reexecColumns+` FROM reexec_runs WHERE dataset_id=$1 ORDER BY id DESC LIMIT 100`, dataset)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanReexec)
}
func (s *Store) ReexecRun(ctx context.Context, dataset, id int64) (ReexecRun, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+reexecColumns+` FROM reexec_runs WHERE dataset_id=$1 AND id=$2`, dataset, id)
	if err != nil {
		return ReexecRun{}, err
	}
	return one(rows, scanReexec)
}
func (s *Store) ReexecSteps(ctx context.Context, id, after int64, class, height string, limit int) ([]reexec.Step, error) {
	rows, err := s.pool.Query(ctx, `SELECT record FROM reexec_steps WHERE run_id=$1 AND execution_ordinal>$2 AND ($3='' OR class=$3) AND ($4='' OR height=nullif($4,'')::numeric) ORDER BY execution_ordinal LIMIT $5`, id, after, class, height, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.CollectableRow) (reexec.Step, error) {
		var x reexec.Step
		var raw []byte
		err := r.Scan(&raw)
		if err == nil {
			err = json.Unmarshal(raw, &x)
		}
		return x, err
	})
}

// ReexecDataset provides private command provenance without changing import state.
func (s *Store) ReexecDataset(ctx context.Context, id int64) (Dataset, NetworkKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+datasetColumns+` FROM datasets WHERE id=$1 AND kind='messages'`, id)
	if err != nil {
		return Dataset{}, NetworkKey{}, err
	}
	d, err := one(rows, scanDataset)
	if err != nil {
		return d, NetworkKey{}, err
	}
	var n NetworkKey
	err = s.pool.QueryRow(ctx, `SELECT chain_id::text,genesis_hash,name FROM networks WHERE id=$1`, d.NetworkID).Scan(&n.ChainID, &n.GenesisHash, &n.Name)
	return d, n, err
}
