package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

type DatasetInputStorage struct {
	State string `json:"state"`
	Files int64  `json:"input_files"`
	Bytes int64  `json:"input_bytes"`
}

func (s *Store) DatasetInputStorage(ctx context.Context, network, id int64) (DatasetInputStorage, error) {
	var out DatasetInputStorage
	var state string
	e := s.pool.QueryRow(ctx, `SELECT status FROM datasets WHERE id=$1 AND network_id=$2`, id, network).Scan(&state)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if e != nil {
		return out, e
	}
	if state == "deleting" {
		d, e := s.DatasetDeletion(ctx, network, id)
		return DatasetInputStorage{State: "deleting", Files: d.Files, Bytes: d.Bytes}, e
	}
	n, e := s.inputNamespace(ctx, id)
	if errors.Is(e, ErrNotFound) {
		var count int64
		e = s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM input_files WHERE dataset_id=$1)+(SELECT count(*) FROM reexec_runs WHERE dataset_id=$1)`, id).Scan(&count)
		out.State = "empty"
		if count > 0 {
			out.State = "unmanaged"
		}
		return out, e
	}
	if e != nil {
		return out, e
	}
	owner, e := s.StorageOwner(ctx)
	if e != nil {
		return out, e
	}
	if n.Owner != owner {
		out.State = "foreign"
		return out, nil
	}
	out.Files, out.Bytes, e = n.Inspect()
	if e != nil {
		out.State = "unavailable"
		return out, nil
	}
	var other bool
	e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM input_files WHERE dataset_id=$1 AND path<>$2||'/'||sha256 UNION ALL SELECT 1 FROM reexec_runs WHERE dataset_id=$1 AND chain_path<>$2||'/'||COALESCE(summary->>'chain_sha256',''))`, id, n.Directory()).Scan(&other)
	if e != nil {
		return out, e
	}
	out.State = "owned"
	if other {
		out.State = "unmanaged"
	}
	return out, nil
}
