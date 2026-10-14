package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/jackc/pgx/v5"
)

type ScenarioSource struct {
	Dataset                                     int64
	ID, DeclarationSHA, SourceSHA, ExecutionSHA string
	Snapshot                                    scenario.SourceSnapshot
}

const scenarioSourceColumns = `dataset_id,source_id,declaration_sha256,source_sha256,execution_sha256,snapshot`

func scanScenarioSource(row pgx.Row) (ScenarioSource, error) {
	var s ScenarioSource
	var raw []byte
	err := row.Scan(&s.Dataset, &s.ID, &s.DeclarationSHA, &s.SourceSHA, &s.ExecutionSHA, &raw)
	if err == nil {
		err = json.Unmarshal(raw, &s.Snapshot)
	}
	return s, err
}
func (s *Store) ScenarioSource(ctx context.Context, dataset int64, id string) (ScenarioSource, error) {
	result, err := scanScenarioSource(s.pool.QueryRow(ctx, `SELECT `+scenarioSourceColumns+` FROM scenario_sources WHERE dataset_id=$1 AND source_id=$2`, dataset, id))
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return result, err
}
func (s *Store) ScenarioSources(ctx context.Context, dataset int64) ([]ScenarioSource, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scenarioSourceColumns+` FROM scenario_sources WHERE dataset_id=$1 ORDER BY source_id`, dataset)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.CollectableRow) (ScenarioSource, error) { return scanScenarioSource(r) })
}

// PutScenarioSource binds an operator ID once. Changed declarations or bytes
// require a new ID rather than silently changing queued jobs after restart.
func (s *Store) PutScenarioSource(ctx context.Context, source ScenarioSource) error {
	if source.Dataset < 1 || !logs.Identifier(source.ID) || !whatifSHA.MatchString(source.DeclarationSHA) || !whatifSHA.MatchString(source.SourceSHA) || source.ExecutionSHA != "" && !whatifSHA.MatchString(source.ExecutionSHA) || len(source.Snapshot.Events) > 256 {
		return ErrScenarioState
	}
	release, err := s.DatasetReadLease(ctx, source.Dataset)
	if err != nil {
		return err
	}
	defer release()
	directory, err := s.InputStorageDirectory(ctx, source.Dataset)
	if err != nil {
		return err
	}
	for _, event := range source.Snapshot.Events {
		if !logs.Identifier(event.Source.ID) || event.Source.Kind != "events" || event.Source.Node == "" || !whatifSHA.MatchString(event.Source.SHA256) || len(event.Files) < 1 || len(event.Files) > 4 {
			return ErrScenarioState
		}
	}
	var total int64
	for _, object := range source.Snapshot.Objects() {
		if object.Bytes < 1 || object.Bytes > 256<<20 || !whatifSHA.MatchString(object.SHA256) || filepath.Dir(object.Path) != directory || filepath.Base(object.Path) != object.SHA256 || total > (16<<30)-object.Bytes {
			return ErrScenarioState
		}
		total += object.Bytes
	}
	raw, err := json.Marshal(source.Snapshot)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO scenario_sources(dataset_id,source_id,declaration_sha256,source_sha256,execution_sha256,snapshot) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(dataset_id,source_id) DO UPDATE SET source_id=EXCLUDED.source_id WHERE scenario_sources.declaration_sha256=EXCLUDED.declaration_sha256 AND scenario_sources.source_sha256=EXCLUDED.source_sha256 AND scenario_sources.execution_sha256=EXCLUDED.execution_sha256 AND scenario_sources.snapshot=EXCLUDED.snapshot`, source.Dataset, source.ID, source.DeclarationSHA, source.SourceSHA, source.ExecutionSHA, raw)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrScenarioState
	}
	return err
}
