package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/reconstruct"
	"github.com/jackc/pgx/v5"
)

var ErrReconstructionSource = errors.New("reconstruction does not match a completed log source")

type ReconstructionRun struct {
	ID          int64     `json:"id"`
	Dataset     int64     `json:"dataset_id"`
	Input       string    `json:"input_id"`
	From        string    `json:"from_height"`
	To          string    `json:"to_height"`
	SHA256      string    `json:"result_sha256"`
	Created     time.Time `json:"created_at"`
	Heights     int64     `json:"heights"`
	Complete    int64     `json:"complete_heights"`
	Steps       int64     `json:"steps"`
	Differences int64     `json:"difference_candidates"`
}

// Summary retains the source and height assessments. Step arrays are empty;
// immutable execution pages provide the full compared projections separately.
type ReconstructionDetail struct {
	ReconstructionRun
	Summary reconstruct.ExecutionResult `json:"summary"`
}

type ReconstructionStep struct {
	Position int64                     `json:"position"`
	Height   string                    `json:"height"`
	Run      string                    `json:"log_run"`
	Step     reconstruct.ExecutionStep `json:"step"`
}

// PutReconstruction atomically stores a finished, source-bound execution. It
// cannot change imported log facts or finalise a partially written result.
func (s *Store) PutReconstruction(ctx context.Context, dataset int64, input string, result reconstruct.ExecutionResult) (int64, error) {
	if result.ExecutionVersion != reconstruct.ExecutionVersion || result.ComparisonModel != reconstruct.ComparisonModel || !result.AllImprovementsOff || len(result.Heights) == 0 || len(result.Heights) > reconstruct.MaxHeights {
		return 0, ErrReconstructionSource
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 64<<20 {
		return 0, ErrReconstructionSource
	}
	hash := sha256.Sum256(raw)
	identity := hex.EncodeToString(hash[:])
	summary := result
	summary.Executions = make([]reconstruct.HeightExecution, len(result.Executions))
	var steps, differences, complete int64
	for _, height := range result.Heights {
		if height.Status == "complete" {
			complete++
		}
	}
	for i, execution := range result.Executions {
		summary.Executions[i] = execution
		summary.Executions[i].Steps = []reconstruct.ExecutionStep{}
		steps += int64(len(execution.Steps))
		for _, step := range execution.Steps {
			differences += int64(len(step.Differences))
		}
	}
	metadata, err := json.Marshal(summary)
	if err != nil {
		return 0, err
	}
	release, err := s.DatasetReadLease(ctx, dataset)
	if err != nil {
		return 0, err
	}
	defer release()
	var id int64
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var matches bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM datasets d JOIN networks n ON n.id=d.network_id JOIN log_inputs i ON i.dataset_id=d.id WHERE d.id=$1 AND d.kind='run' AND d.status='complete' AND i.input_id=$2 AND i.kind='log' AND i.sha256=$3 AND i.bytes=$4 AND i.node=$5 AND i.profile=$6 AND i.profile_sha256=$7 AND n.chain_id=$8 AND n.genesis_hash=$9)`, dataset, input, result.Sources.LogSHA, result.Sources.LogBytes, result.Node, result.Sources.LogProfile, result.Sources.LogProfileSHA, result.ChainID, result.GenesisHash).Scan(&matches); e != nil {
			return e
		}
		if !matches {
			return ErrReconstructionSource
		}
		// A duplicate closed result returns the original ID without mutation.
		e := tx.QueryRow(ctx, `INSERT INTO reconstruction_runs(dataset_id,input_id,from_height,to_height,result_sha256,height_count,complete_heights,step_count,differences,summary) VALUES($1,$2,$3::numeric,$4::numeric,$5,$6,$7,$8,$9,$10) ON CONFLICT(dataset_id,input_id,result_sha256) DO NOTHING RETURNING id`, dataset, input, result.From, result.To, identity, len(result.Heights), complete, steps, differences, metadata).Scan(&id)
		if errors.Is(e, pgx.ErrNoRows) {
			return tx.QueryRow(ctx, `SELECT id FROM reconstruction_runs WHERE dataset_id=$1 AND input_id=$2 AND result_sha256=$3`, dataset, input, identity).Scan(&id)
		}
		if e != nil {
			return e
		}
		position := int64(0)
		batch := &pgx.Batch{}
		for _, execution := range result.Executions {
			for _, step := range execution.Steps {
				position++
				record, e := json.Marshal(step)
				if e != nil {
					return e
				}
				batch.Queue(`INSERT INTO reconstruction_steps(run_id,position,height,log_run,different,record) VALUES($1,$2,$3::numeric,$4,$5,$6)`, id, position, execution.Height, execution.Run, len(step.Differences) > 0, record)
			}
		}
		if position == 0 {
			return nil
		}
		pending := tx.SendBatch(ctx, batch)
		for range position {
			if _, e := pending.Exec(); e != nil {
				_ = pending.Close()
				return e
			}
		}
		return pending.Close()
	})
	return id, err
}

const reconstructionColumns = `id,dataset_id,input_id,from_height::text,to_height::text,result_sha256,created_at,height_count,complete_heights,step_count,differences`

func reconstructionFields(row *ReconstructionRun) []any {
	return []any{&row.ID, &row.Dataset, &row.Input, &row.From, &row.To, &row.SHA256, &row.Created, &row.Heights, &row.Complete, &row.Steps, &row.Differences}
}
func (s *Store) ReconstructionRuns(ctx context.Context, dataset int64) ([]ReconstructionRun, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+reconstructionColumns+` FROM reconstruction_runs WHERE dataset_id=$1 ORDER BY id DESC LIMIT 100`, dataset)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.CollectableRow) (ReconstructionRun, error) {
		var x ReconstructionRun
		err := r.Scan(reconstructionFields(&x)...)
		return x, err
	})
}
func (s *Store) ReconstructionRun(ctx context.Context, dataset, id int64) (ReconstructionDetail, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+reconstructionColumns+`,summary FROM reconstruction_runs WHERE dataset_id=$1 AND id=$2`, dataset, id)
	if err != nil {
		return ReconstructionDetail{}, err
	}
	return one(rows, func(r pgx.CollectableRow) (ReconstructionDetail, error) {
		var x ReconstructionDetail
		var raw []byte
		err := r.Scan(append(reconstructionFields(&x.ReconstructionRun), &raw)...)
		if err == nil {
			err = json.Unmarshal(raw, &x.Summary)
		}
		return x, err
	})
}
func (s *Store) ReconstructionSteps(ctx context.Context, id, after int64, height, run string, different bool, limit int) ([]ReconstructionStep, error) {
	rows, err := s.pool.Query(ctx, `SELECT position,height::text,log_run,record FROM reconstruction_steps WHERE run_id=$1 AND position>$2 AND ($3='' OR height=nullif($3,'')::numeric) AND ($4='' OR log_run=$4) AND (NOT $5 OR different) ORDER BY position LIMIT $6`, id, after, height, run, different, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.CollectableRow) (ReconstructionStep, error) {
		var x ReconstructionStep
		var raw []byte
		err := r.Scan(&x.Position, &x.Height, &x.Run, &raw)
		if err == nil {
			err = json.Unmarshal(raw, &x.Step)
		}
		return x, err
	})
}
