package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
	"github.com/jackc/pgx/v5"
)

func (s *Store) BeginRuntime(ctx context.Context, k NetworkKey, name string, meta json.RawMessage) (Dataset, func(), error) {
	return s.beginDataset(ctx, k, name, "runtime", meta)
}
func (s *Store) PutRuntime(ctx context.Context, id int64, c runtimeobs.Capture) error {
	if e := c.Validate(); e != nil {
		return e
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return e
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var kind string
		if e := tx.QueryRow(ctx, `SELECT kind FROM datasets WHERE id=$1 FOR UPDATE`, id).Scan(&kind); e != nil {
			return e
		}
		if kind != "runtime" {
			return errors.New("wrong runtime dataset kind")
		}
		tag, e := tx.Exec(ctx, `INSERT INTO runtime_observation_captures(dataset_id,capture) VALUES($1,$2) ON CONFLICT(dataset_id) DO UPDATE SET capture=runtime_observation_captures.capture WHERE runtime_observation_captures.capture=EXCLUDED.capture`, id, raw)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return errors.New("runtime source content conflict")
		}
		return nil
	})
}
func (s *Store) RuntimeCapture(ctx context.Context, id int64) (runtimeobs.Capture, error) {
	var raw []byte
	var c runtimeobs.Capture
	e := s.pool.QueryRow(ctx, `SELECT c.capture FROM runtime_observation_captures c JOIN datasets d ON d.id=c.dataset_id WHERE c.dataset_id=$1 AND d.status='complete'`, id).Scan(&raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	if e != nil {
		return c, e
	}
	e = json.Unmarshal(raw, &c)
	return c, e
}
