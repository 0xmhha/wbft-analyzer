package store

import (
	"context"
	"errors"

	"github.com/0xmhha/wbft-analyzer/internal/privacy"
	"github.com/jackc/pgx/v5"
)

var ErrBuildScope = errors.New("store: build visibility does not match the deployment")

func checkScope(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) error {
	var present bool
	if err := q.QueryRow(ctx, `SELECT to_regclass(current_schema()||'.deployment_scope') IS NOT NULL`).Scan(&present); err != nil {
		return err
	}
	if !present {
		return nil
	}
	var scope string
	err := q.QueryRow(ctx, `SELECT visibility FROM deployment_scope WHERE singleton`).Scan(&scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if scope != privacy.Visibility() {
		return ErrBuildScope
	}
	return nil
}

func (s *Store) claimScope(ctx context.Context) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `LOCK TABLE deployment_scope IN EXCLUSIVE MODE`); err != nil {
			return err
		}
		if err := checkScope(ctx, tx); err != nil {
			return err
		}
		scope := privacy.Visibility()
		if _, err := tx.Exec(ctx, `INSERT INTO deployment_scope(singleton,visibility) VALUES(true,$1) ON CONFLICT DO NOTHING`, scope); err != nil {
			return err
		}
		if scope == "private" {
			_, err := tx.Exec(ctx, `UPDATE networks SET visibility='private' WHERE visibility<>'private'; UPDATE datasets SET visibility='private' WHERE visibility<>'private'`)
			return err
		}
		var private bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM networks WHERE visibility='private') OR EXISTS(SELECT 1 FROM datasets WHERE visibility='private') OR EXISTS(SELECT 1 FROM reports WHERE inspector_build<>'public')`).Scan(&private); err != nil {
			return err
		}
		if private {
			return ErrBuildScope
		}
		return nil
	})
}
