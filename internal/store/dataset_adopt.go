package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/0xmhha/wbft-analyzer/internal/inputs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/jackc/pgx/v5"
)

// AdoptDatasetInputs verifies and copies known objects into this database's
// namespace. Shared legacy and source-database objects are never removed.
func (s *Store) AdoptDatasetInputs(ctx context.Context, network, id int64, directory string) error {
	release, e := s.datasetLease(ctx, id, false, false)
	if e != nil {
		return e
	}
	defer release()
	var eligible bool
	e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM datasets WHERE id=$1 AND network_id=$2 AND kind='messages') AND NOT EXISTS(SELECT 1 FROM reexec_jobs WHERE dataset_id=$1 AND status IN ('queued','running')) AND NOT EXISTS(SELECT 1 FROM whatif_runs WHERE dataset_id=$1 AND status='running') AND NOT EXISTS(SELECT 1 FROM whatif_jobs WHERE dataset_id=$1 AND status IN ('queued','running'))`, id, network).Scan(&eligible)
	if e != nil {
		return e
	}
	if !eligible {
		return ErrDatasetBusy
	}
	root, e := inputs.PrivateRoot(directory)
	if e != nil {
		return e
	}
	owner, e := s.StorageOwner(ctx)
	if e != nil {
		return e
	}
	token, e := inputs.NewToken()
	if e != nil {
		return e
	}
	old, oldErr := s.inputNamespace(ctx, id)
	if oldErr != nil && !errors.Is(oldErr, ErrNotFound) {
		return oldErr
	}
	if oldErr == nil && old.Owner == owner {
		if old.Root != root {
			return inputs.ErrOwnership
		}
		token = old.Token
	}
	_, e = s.pool.Exec(ctx, `INSERT INTO dataset_storage_adoptions(dataset_id,root,token,owner) VALUES($1,$2,$3,$4) ON CONFLICT(dataset_id) DO NOTHING`, id, root, token, owner)
	if e != nil {
		return e
	}
	var n inputs.Namespace
	e = s.pool.QueryRow(ctx, `SELECT root,token,owner FROM dataset_storage_adoptions WHERE dataset_id=$1`, id).Scan(&n.Root, &n.Token, &n.Owner)
	if e != nil {
		return e
	}
	if n.Root != root || n.Owner != owner {
		return inputs.ErrOwnership
	}
	if e = n.Ensure(); e != nil {
		return e
	}
	type object struct {
		path, sha string
		bytes     int64
	}
	objects := []object{}
	rows, e := s.pool.Query(ctx, `SELECT path,sha256,bytes FROM input_files WHERE dataset_id=$1`, id)
	if e != nil {
		return e
	}
	for rows.Next() {
		var o object
		if e = rows.Scan(&o.path, &o.sha, &o.bytes); e != nil {
			rows.Close()
			return e
		}
		objects = append(objects, o)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = s.pool.Query(ctx, `SELECT chain_path,COALESCE(summary->>'chain_sha256','') FROM reexec_runs WHERE dataset_id=$1 UNION ALL SELECT chain_path,chain_sha256 FROM whatif_runs WHERE dataset_id=$1`, id)
	if e != nil {
		return e
	}
	for rows.Next() {
		var o object
		if e = rows.Scan(&o.path, &o.sha); e != nil {
			rows.Close()
			return e
		}
		info, err := os.Lstat(o.path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			rows.Close()
			return inputs.ErrOwnership
		}
		o.bytes = info.Size()
		objects = append(objects, o)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, o := range objects {
		info, err := os.Lstat(o.path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != o.bytes {
			return inputs.ErrOwnership
		}
		if filepath.Base(o.path) != o.sha {
			return inputs.ErrOwnership
		}
		plan := messages.Prepared{Input: messages.Input{ID: "adopt", Path: filepath.Dir(o.path)}, Summary: messages.Summary{Files: []messages.File{{Name: filepath.Base(o.path), SHA256: o.sha, Bytes: o.bytes}}}}
		if _, e = messages.Archive(ctx, n.Directory(), []messages.Prepared{plan}); e != nil {
			return e
		}
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO dataset_storage(dataset_id,root,token,owner) VALUES($1,$2,$3,$4) ON CONFLICT(dataset_id) DO UPDATE SET root=EXCLUDED.root,token=EXCLUDED.token,owner=EXCLUDED.owner`, id, n.Root, n.Token, n.Owner); e != nil {
			return e
		}
		for _, o := range objects {
			sha := o.sha
			path := filepath.Join(n.Directory(), sha)
			if _, e := tx.Exec(ctx, `UPDATE input_files SET path=$3 WHERE dataset_id=$1 AND sha256=$2`, id, sha, path); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `UPDATE reexec_runs SET chain_path=$3 WHERE dataset_id=$1 AND summary->>'chain_sha256'=$2`, id, sha, path); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `UPDATE whatif_runs SET chain_path=$3 WHERE dataset_id=$1 AND chain_sha256=$2`, id, sha, path); e != nil {
				return e
			}
		}
		_, e := tx.Exec(ctx, `DELETE FROM dataset_storage_adoptions WHERE dataset_id=$1`, id)
		return e
	})
}
