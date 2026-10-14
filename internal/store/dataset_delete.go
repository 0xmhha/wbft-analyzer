package store

import (
	"context"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/inputs"
	"github.com/jackc/pgx/v5"
)

var ErrDatasetReferenced = errors.New("dataset is referenced by a follow capture")
var ErrDatasetConfirm = errors.New("dataset name confirmation does not match")

type DatasetDeletion struct {
	Dataset  int64      `json:"dataset_id"`
	Network  int64      `json:"network_id"`
	Name     string     `json:"name"`
	Status   string     `json:"status"`
	Files    int64      `json:"input_files"`
	Bytes    int64      `json:"input_bytes"`
	Created  time.Time  `json:"created_at"`
	Finished *time.Time `json:"finished_at"`
}

const deletionColumns = `dataset_id,network_id,name,status,files,bytes,created_at,finished_at`

func scanDeletion(row pgx.Row) (DatasetDeletion, error) {
	var d DatasetDeletion
	e := row.Scan(&d.Dataset, &d.Network, &d.Name, &d.Status, &d.Files, &d.Bytes, &d.Created, &d.Finished)
	return d, e
}
func (s *Store) DatasetDeletion(ctx context.Context, network, id int64) (DatasetDeletion, error) {
	rows, e := s.pool.Query(ctx, `SELECT `+deletionColumns+` FROM dataset_deletions WHERE network_id=$1 AND dataset_id=$2`, network, id)
	if e != nil {
		return DatasetDeletion{}, e
	}
	return one(rows, func(r pgx.CollectableRow) (DatasetDeletion, error) { return scanDeletion(r) })
}

// DeleteDataset fences imports and replays, commits deletion intent, cleans
// only an owned namespace, then removes rows. Failed cleanup is retryable.
func (s *Store) DeleteDataset(ctx context.Context, network, id int64, confirm string) (DatasetDeletion, error) {
	release, e := s.datasetLease(ctx, id, false, true)
	if e != nil {
		return DatasetDeletion{}, e
	}
	defer release()
	prior, e := s.DatasetDeletion(ctx, network, id)
	if e == nil {
		if prior.Name != confirm {
			return prior, ErrDatasetConfirm
		}
		if prior.Status == "deleted" {
			return prior, nil
		}
		return s.finishDatasetDeletion(ctx, prior)
	}
	if !errors.Is(e, ErrNotFound) {
		return DatasetDeletion{}, e
	}
	var name string
	e = s.pool.QueryRow(ctx, `SELECT name FROM datasets WHERE id=$1 AND network_id=$2`, id, network).Scan(&name)
	if errors.Is(e, pgx.ErrNoRows) {
		return DatasetDeletion{}, ErrNotFound
	}
	if e != nil {
		return DatasetDeletion{}, e
	}
	if name != confirm {
		return DatasetDeletion{}, ErrDatasetConfirm
	}
	n, e := s.inputNamespace(ctx, id)
	managed := e == nil
	if e != nil && !errors.Is(e, ErrNotFound) {
		return DatasetDeletion{}, e
	}
	var files, size int64
	if managed {
		owner, err := s.StorageOwner(ctx)
		if err != nil {
			return DatasetDeletion{}, err
		}
		if owner != n.Owner {
			return DatasetDeletion{}, inputs.ErrOwnership
		}
		files, size, e = n.Inspect()
		if e != nil {
			return DatasetDeletion{}, e
		}
	}
	var result DatasetDeletion
	e = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var activeExperiment bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM whatif_runs WHERE dataset_id=$1 AND status='running') OR EXISTS(SELECT 1 FROM whatif_jobs WHERE dataset_id=$1 AND status='running')`, id).Scan(&activeExperiment); err != nil {
			return err
		}
		if activeExperiment {
			return ErrDatasetBusy
		}
		var dependency, adopting bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM follow_batches WHERE headers_dataset=$1 OR observations_dataset=$1),EXISTS(SELECT 1 FROM dataset_storage_adoptions WHERE dataset_id=$1)`, id).Scan(&dependency, &adopting); e != nil {
			return e
		}
		if dependency {
			return ErrDatasetReferenced
		}
		if adopting {
			return ErrDatasetBusy
		}
		rows, e := tx.Query(ctx, `SELECT status FROM reexec_jobs WHERE dataset_id=$1 FOR UPDATE`, id)
		if e != nil {
			return e
		}
		for rows.Next() {
			var status string
			if e = rows.Scan(&status); e != nil {
				rows.Close()
				return e
			}
			if status == "running" {
				rows.Close()
				return ErrDatasetBusy
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		refs, e := tx.Query(ctx, `SELECT path,sha256 FROM input_files WHERE dataset_id=$1 UNION ALL SELECT chain_path,COALESCE(summary->>'chain_sha256','') FROM reexec_runs WHERE dataset_id=$1 UNION ALL SELECT chain_path,chain_sha256 FROM whatif_runs WHERE dataset_id=$1`, id)
		if e != nil {
			return e
		}
		for refs.Next() {
			var path, sha string
			if e = refs.Scan(&path, &sha); e != nil {
				refs.Close()
				return e
			}
			if !managed || !ownedPath(n, path, sha) {
				refs.Close()
				return ErrUnmanagedInputs
			}
		}
		e = refs.Err()
		refs.Close()
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE reexec_jobs SET status='cancelled',issue='dataset_deleted',finished_at=now() WHERE dataset_id=$1 AND status='queued'`, id); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE whatif_jobs SET status='cancelled',issue='dataset_deleted',finished_at=now() WHERE dataset_id=$1 AND status='queued'`, id); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE datasets SET status='deleting',updated_at=now() WHERE id=$1 AND network_id=$2`, id, network); e != nil {
			return e
		}
		result, e = scanDeletion(tx.QueryRow(ctx, `INSERT INTO dataset_deletions(dataset_id,network_id,name,status,root,token,owner,files,bytes) VALUES($1,$2,$3,'deleting',$4,$5,$6,$7,$8) RETURNING `+deletionColumns, id, network, name, n.Root, n.Token, n.Owner, files, size))
		return e
	})
	if e != nil {
		return DatasetDeletion{}, e
	}
	return s.finishDatasetDeletion(ctx, result)
}
func (s *Store) finishDatasetDeletion(ctx context.Context, d DatasetDeletion) (DatasetDeletion, error) {
	var n inputs.Namespace
	e := s.pool.QueryRow(ctx, `SELECT root,token,owner FROM dataset_deletions WHERE dataset_id=$1 AND network_id=$2 AND status='deleting'`, d.Dataset, d.Network).Scan(&n.Root, &n.Token, &n.Owner)
	if e != nil {
		return d, e
	}
	if n.Token != "" {
		owner, err := s.StorageOwner(ctx)
		if err != nil {
			return d, err
		}
		if owner != n.Owner {
			return d, inputs.ErrOwnership
		}
		if e = n.Clean(ctx); e != nil {
			return d, e
		}
	}
	e = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, table := range []string{"reexec_jobs", "reexec_runs", "whatif_jobs", "whatif_runs", "dataset_storage"} {
			if _, e := tx.Exec(ctx, `DELETE FROM `+table+` WHERE dataset_id=$1`, d.Dataset); e != nil {
				return e
			}
		}
		if _, e := tx.Exec(ctx, `DELETE FROM datasets WHERE id=$1 AND network_id=$2 AND status='deleting'`, d.Dataset, d.Network); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `UPDATE dataset_deletions SET status='deleted',finished_at=now() WHERE dataset_id=$1 AND network_id=$2`, d.Dataset, d.Network)
		return e
	})
	if e != nil {
		return d, e
	}
	return s.DatasetDeletion(ctx, d.Network, d.Dataset)
}
