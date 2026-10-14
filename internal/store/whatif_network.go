package store

import (
	"context"
	"encoding/json"
	derived "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/whatif"
	"github.com/jackc/pgx/v5"
)

type WhatifNetworkBinding struct {
	ID       string                `json:"id"`
	Evidence whatif.NetworkBinding `json:"evidence"`
}

func lockWhatif(ctx context.Context, tx pgx.Tx, id int64) error {
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM whatif_runs WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
		return err
	}
	if status != "running" {
		return ErrWhatifState
	}
	return nil
}

// PutWhatifNetworkBindings pins the original frame associations before any
// changed execution is stored. Readers never observe a partially loaded set.
func (s *Store) PutWhatifNetworkBindings(ctx context.Context, id int64, bindings []whatif.NetworkBinding) error {
	if len(bindings) > 1000000 {
		return whatif.ErrEvidence
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockWhatif(ctx, tx, id); err != nil {
			return err
		}
		for index, b := range bindings {
			if b.Sends == nil {
				b.Sends = []derived.Source{}
			}
			if b.Receives == nil {
				b.Receives = []derived.Source{}
			}
			raw, err := json.Marshal(b)
			if err != nil {
				return err
			}
			q := b.Original
			if _, err = tx.Exec(ctx, `INSERT INTO whatif_network_bindings(run_id,id,writer_run,engine_run,step,ordinal,output,record) VALUES($1,$2,$3,$4::numeric,$5::numeric,$6::numeric,$7::numeric,$8)`, id, index+1, q.Source.Writer, q.Source.Engine, q.Source.Step, q.Source.Ordinal, q.Output, raw); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) PutWhatifNetworkEffects(ctx context.Context, id int64, effects []whatif.NetworkEffect) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return putWhatifEffects(ctx, tx, id, effects) })
}

// PutWhatifStepWithEffects stores the execution and its independently derived
// effects atomically. A rejected effect cannot leave an unlinked input row.
func (s *Store) PutWhatifStepWithEffects(ctx context.Context, id int64, step whatif.Step, effects []whatif.NetworkEffect) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := putWhatifStep(ctx, tx, id, step); err != nil {
			return err
		}
		for _, effect := range effects {
			if effect.Current == nil || effect.Current.Execution != step.Execution || effect.Current.Mono != step.Mono {
				return whatif.ErrEvidence
			}
			index, err := strconv.ParseUint(effect.Current.Output, 10, 64)
			if err != nil || index == 0 || index > uint64(len(step.Actions)) || effect.ActionKind != step.Actions[index-1].Kind || effect.PayloadSHA256 != step.Actions[index-1].PayloadSHA256 {
				return whatif.ErrEvidence
			}
		}
		return putWhatifEffects(ctx, tx, id, effects)
	})
}
func putWhatifEffects(ctx context.Context, tx pgx.Tx, id int64, effects []whatif.NetworkEffect) error {
	if len(effects) > 1000000 {
		return whatif.ErrEvidence
	}

	if err := lockWhatif(ctx, tx, id); err != nil {
		return err
	}
	var previous uint64
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(id),0) FROM whatif_network_effects WHERE run_id=$1`, id).Scan(&previous); err != nil {
		return err
	}
	for _, effect := range effects {
		n, err := strconv.ParseUint(effect.ID, 10, 64)
		if err != nil || n != previous+1 || strconv.FormatUint(n, 10) != effect.ID {
			return whatif.ErrEvidence
		}
		var execution, output *string
		if effect.Current != nil {
			execution = &effect.Current.Execution
			output = &effect.Current.Output
		}
		raw, err := json.Marshal(effect)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO whatif_network_effects(run_id,id,execution_step,output,kind,record) VALUES($1,$2,$3::bigint,$4::numeric,$5,$6)`, id, n, execution, output, effect.Kind, raw); err != nil {
			return err
		}
		previous = n
	}
	return nil
}
func (s *Store) WhatifNetworkBindings(ctx context.Context, id, after int64, limit int) ([]WhatifNetworkBinding, error) {
	if id < 1 || after < 0 || limit < 1 || limit > 1001 {
		return nil, whatif.ErrEvidence
	}
	rows, err := s.pool.Query(ctx, `SELECT id,record FROM whatif_network_bindings WHERE run_id=$1 AND id>$2 ORDER BY id LIMIT $3`, id, after, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(row pgx.CollectableRow) (WhatifNetworkBinding, error) {
		var b WhatifNetworkBinding
		var n int64
		var raw []byte
		err := row.Scan(&n, &raw)
		if err == nil {
			err = json.Unmarshal(raw, &b.Evidence)
		}
		b.ID = strconv.FormatInt(n, 10)
		return b, err
	})
}

func (s *Store) WhatifNetworkEffects(ctx context.Context, id, after int64, limit int) ([]whatif.NetworkEffect, error) {
	if id < 1 || after < 0 || limit < 1 || limit > 1001 {
		return nil, whatif.ErrEvidence
	}
	rows, err := s.pool.Query(ctx, `SELECT record FROM whatif_network_effects WHERE run_id=$1 AND id>$2 ORDER BY id LIMIT $3`, id, after, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(row pgx.CollectableRow) (whatif.NetworkEffect, error) {
		var e whatif.NetworkEffect
		var raw []byte
		err := row.Scan(&raw)
		if err == nil {
			err = json.Unmarshal(raw, &e)
		}
		return e, err
	})
}
