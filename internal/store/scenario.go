package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/jackc/pgx/v5"
)

var ErrScenarioState = errors.New("scenario experiment finalised or out of order")

func (s *Store) BeginScenario(ctx context.Context, e scenario.Experiment) (int64, error) {
	return beginScenario(ctx, s.pool, e)
}

type scenarioBeginner interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func beginScenario(ctx context.Context, q scenarioBeginner, e scenario.Experiment) (int64, error) {
	p, hash, err := scenario.SealProvenance(e.Provenance)
	if err != nil {
		return 0, err
	}
	change, changeHash, err := e.Change.Canonical()
	if err != nil {
		return 0, err
	}
	if !whatifSHA.MatchString(e.ExecutionSHA256) || e.Version != scenario.ExperimentVersion || e.From < 1 || e.To < e.From || e.To-e.From >= 10000 || e.SourceSHA256 != hash || e.ChangeSHA256 != changeHash || e.Model.Version != scenario.FitVersion || e.Model.Status != "complete" && e.Model.Status != "partial" {
		return 0, ErrScenarioState
	}
	if err := scenario.ValidateRecorded(e.RecordedHeights, e.RecordedCounts, e.From, e.To); err != nil {
		return 0, err
	}
	e.RecordedHeights = append([]scenario.Height{}, e.RecordedHeights...)
	recordedHash := scenario.RecordedHash(e.RecordedHeights)
	if e.RecordedSHA256 != "" && e.RecordedSHA256 != recordedHash {
		return 0, ErrScenarioState
	}
	e.RecordedSHA256 = recordedHash
	e.Provenance = p
	e.Status = "running"
	e.Baseline = nil
	e.BaselineTime = nil
	e.TimeCheck = "pending"
	if _, err := scenario.RunHomogeneity(e.RecordedCounts); err != nil {
		return 0, err
	}
	provenance, _ := json.Marshal(p)
	summary, err := json.Marshal(e)
	if err != nil {
		return 0, err
	}
	var id int64
	err = q.QueryRow(ctx, `INSERT INTO scenario_runs(dataset_id,provenance,source_sha256,change,change_sha256,status,summary) VALUES($1,$2,$3,$4,$5,'running',$6) RETURNING id`, p.Dataset, provenance, hash, change, changeHash, summary).Scan(&id)
	return id, err
}

func (s *Store) PutScenarioSeed(ctx context.Context, id int64, record scenario.SeedRecord) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var status string
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT status,summary FROM scenario_runs WHERE id=$1 FOR UPDATE`, id).Scan(&status, &raw); err != nil {
			return err
		}
		if status != "running" {
			return ErrScenarioState
		}
		var e scenario.Experiment
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		if record.Mode != "baseline" && record.Mode != "counterfactual" {
			return ErrScenarioState
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM scenario_seed_results WHERE run_id=$1 AND mode=$2`, id, record.Mode).Scan(&count); err != nil {
			return err
		}
		r := record.Result
		if count >= len(e.Provenance.Seeds) || r.Seed != e.Provenance.Seeds[count] || r.SimulationNS < 0 || r.Status != "complete" && r.Status != "partial" && r.Status != "violations" || r.Violations < 0 || len(r.Heights) > int(e.To-e.From+1) {
			return ErrScenarioState
		}
		if r.Status == "complete" && (r.Violations != 0 || len(r.Heights) != int(e.To-e.From+1)) {
			return ErrScenarioState
		}
		for i, h := range r.Heights {
			if h.Number != e.From+uint64(i) || h.Time < h.PeriodSeconds || i > 0 && (h.Time < r.Heights[i-1].Time || h.PeriodSeconds != h.Time-r.Heights[i-1].Time) {
				return ErrScenarioState
			}
		}
		if record.Mode == "counterfactual" {
			var baseline int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM scenario_seed_results WHERE run_id=$1 AND mode='baseline'`, id).Scan(&baseline); err != nil {
				return err
			}
			if baseline != len(e.Provenance.Seeds) {
				return ErrScenarioState
			}
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO scenario_seed_results(run_id,mode,seed_index,seed,status,record) VALUES($1,$2,$3,$4,$5,$6)`, id, record.Mode, count+1, r.Seed, r.Status, raw)
		return err
	})
}

func (s *Store) FinishScenario(ctx context.Context, id int64, final scenario.Experiment) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var status string
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT status,summary FROM scenario_runs WHERE id=$1 FOR UPDATE`, id).Scan(&status, &raw); err != nil {
			return err
		}
		if status != "running" || final.Status != "completed" && final.Status != "partial" && final.Status != "failed" {
			return ErrScenarioState
		}
		var original scenario.Experiment
		if err := json.Unmarshal(raw, &original); err != nil {
			return err
		}
		if original.ExecutionSHA256 != final.ExecutionSHA256 || original.SourceSHA256 != final.SourceSHA256 || original.ChangeSHA256 != final.ChangeSHA256 || original.From != final.From || original.To != final.To || !reflect.DeepEqual(original.Model, final.Model) || scenario.RecordedHash(original.RecordedHeights) != scenario.RecordedHash(final.RecordedHeights) || final.RecordedSHA256 != "" && original.RecordedSHA256 != final.RecordedSHA256 {
			return ErrScenarioState
		}
		rows, err := tx.Query(ctx, `SELECT mode,record FROM scenario_seed_results WHERE run_id=$1 ORDER BY mode,seed_index`, id)
		if err != nil {
			return err
		}
		baseline, changed := []scenario.SeedResult{}, []scenario.SeedResult{}
		for rows.Next() {
			var mode string
			var raw []byte
			if err := rows.Scan(&mode, &raw); err != nil {
				rows.Close()
				return err
			}
			var seed scenario.SeedResult
			if err := json.Unmarshal(raw, &seed); err != nil {
				rows.Close()
				return err
			}
			if mode == "baseline" {
				baseline = append(baseline, seed)
			} else {
				changed = append(changed, seed)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		complete := len(baseline) == len(original.Provenance.Seeds) && len(changed) == len(original.Provenance.Seeds)
		baselineComplete := len(baseline) == len(original.Provenance.Seeds)
		counts := []scenario.RoundCount{}
		for _, r := range baseline {
			if r.Status != "complete" {
				complete = false
				baselineComplete = false
			}
			c := scenario.RoundCount{Total: int64(len(r.Heights))}
			for _, h := range r.Heights {
				if h.Round > 0 {
					c.Late++
				}
			}
			counts = append(counts, c)
		}
		for _, r := range changed {
			if r.Status != "complete" {
				complete = false
			}
		}
		if final.Status == "completed" && !complete {
			return ErrScenarioState
		}
		final.Provenance = original.Provenance
		final.Model = original.Model
		final.RecordedCounts = original.RecordedCounts
		final.RecordedHeights = original.RecordedHeights
		final.RecordedSHA256 = original.RecordedSHA256
		final.Change = original.Change
		final.Version = original.Version
		final.TimeCheck = "threshold_unconfigured"
		final.Baseline = nil
		final.BaselineTime = nil
		// The time criterion belongs to the experiment version, independently
		// of subsequent fitting model versions such as processing policies.
		currentTimeMethod := original.Version == scenario.ExperimentVersion
		if currentTimeMethod {
			final.TimeCheck = "unproved"
		}
		if baselineComplete {
			comparison, err := scenario.CompareRounds(original.RecordedCounts, counts, 1)
			if err == nil {
				final.Baseline = &comparison
			}
			if currentTimeMethod {
				timing, err := scenario.EvaluateBaselineTime(original.RecordedHeights, baseline)
				if err != nil {
					return err
				}
				final.BaselineTime = &timing
				final.TimeCheck = timing.Check()
			}
		}
		raw, err = json.Marshal(final)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE scenario_runs SET status=$2,summary=$3,finished_at=now() WHERE id=$1`, id, final.Status, raw)
		return err
	})
}

func (s *Store) ScenarioRun(ctx context.Context, dataset, id int64) (scenario.Experiment, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT summary FROM scenario_runs WHERE id=$1 AND dataset_id=$2`, id, dataset).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return scenario.Experiment{}, ErrNotFound
	}
	if err != nil {
		return scenario.Experiment{}, err
	}
	var result scenario.Experiment
	err = json.Unmarshal(raw, &result)
	return result, err
}

type ScenarioSeed struct {
	Index  int                 `json:"index"`
	Mode   string              `json:"mode"`
	Result scenario.SeedResult `json:"result"`
}

func (s *Store) ScenarioSeeds(ctx context.Context, dataset, id int64, mode string, after, limit int) ([]ScenarioSeed, error) {
	if mode != "baseline" && mode != "counterfactual" || after < 0 || after > 128 || limit < 1 || limit > 129 {
		return nil, ErrScenarioState
	}
	rows, err := s.pool.Query(ctx, `SELECT s.seed_index,s.mode,s.record FROM scenario_seed_results s JOIN scenario_runs r ON r.id=s.run_id WHERE r.dataset_id=$1 AND r.id=$2 AND s.mode=$3 AND s.seed_index>$4 ORDER BY s.seed_index LIMIT $5`, dataset, id, mode, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScenarioSeed{}
	for rows.Next() {
		var result ScenarioSeed
		var raw []byte
		if err := rows.Scan(&result.Index, &result.Mode, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &result.Result); err != nil {
			return nil, err
		}
		out = append(out, result)
	}
	return out, rows.Err()
}

type ScenarioRunInfo struct {
	ID          int64               `json:"id"`
	Summary     scenario.Experiment `json:"summary"`
	Credibility string              `json:"credibility"`
}

func (s *Store) ScenarioRuns(ctx context.Context, dataset int64) ([]ScenarioRunInfo, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,summary FROM scenario_runs WHERE dataset_id=$1 ORDER BY id DESC LIMIT 100`, dataset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScenarioRunInfo{}
	for rows.Next() {
		var r ScenarioRunInfo
		var raw []byte
		if err := rows.Scan(&r.ID, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &r.Summary); err != nil {
			return nil, err
		}
		r.Credibility = r.Summary.Credibility()
		out = append(out, r)
	}
	return out, rows.Err()
}

// ScenarioPlot reads summary and all saved seed rows from one immutable
// database snapshot. A worker cannot mix old and new prefixes in one plot.
func (s *Store) ScenarioPlot(ctx context.Context, dataset, id int64) (scenario.ComparisonPlot, error) {
	out := scenario.ComparisonPlot{}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT summary FROM scenario_runs WHERE dataset_id=$1 AND id=$2`, dataset, id).Scan(&raw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var e scenario.Experiment
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		if err := scenario.ValidateRecorded(e.RecordedHeights, e.RecordedCounts, e.From, e.To); err != nil {
			return err
		}
		if e.RecordedSHA256 != scenario.RecordedHash(e.RecordedHeights) {
			return ErrScenarioState
		}
		rows, err := tx.Query(ctx, `SELECT mode,seed_index,record FROM scenario_seed_results WHERE run_id=$1 ORDER BY mode,seed_index LIMIT 257`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		baseline, changed := []scenario.SeedResult{}, []scenario.SeedResult{}
		count := 0
		for rows.Next() {
			var mode string
			var index int
			var data []byte
			if err := rows.Scan(&mode, &index, &data); err != nil {
				return err
			}
			count++
			if count > 256 {
				return ErrScenarioState
			}
			var seed scenario.SeedResult
			if err := json.Unmarshal(data, &seed); err != nil {
				return err
			}
			switch mode {
			case "baseline":
				if index != len(baseline)+1 {
					return ErrScenarioState
				}
				baseline = append(baseline, seed)
			case "counterfactual":
				if index != len(changed)+1 {
					return ErrScenarioState
				}
				changed = append(changed, seed)
			default:
				return ErrScenarioState
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		out = scenario.Plot(e, baseline, changed)
		return nil
	})
	return out, err
}
