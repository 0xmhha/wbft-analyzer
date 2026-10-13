package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/inputs"
	"github.com/jackc/pgx/v5"
)

var ErrDatasetBusy = errors.New("dataset has an active import or replay")
var ErrDatasetDeleting = errors.New("dataset is being deleted")
var ErrUnmanagedInputs = errors.New("adopt retained inputs before deleting this dataset")

// DatasetReadLease prevents file deletion while a replay prepares or runs.
// Dedicated sessions keep one-connection write pools usable.
func (s *Store) DatasetReadLease(ctx context.Context, id int64) (func(), error) {
	return s.datasetLease(ctx, id, true, false)
}
func (s *Store) datasetLease(ctx context.Context, id int64, shared, allowDeleting bool) (func(), error) {
	conn, e := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if e != nil {
		return nil, e
	}
	closeConn := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(cleanup)
	}
	function := "pg_try_advisory_lock"
	if shared {
		function += "_shared"
	}
	var locked bool
	e = conn.QueryRow(ctx, `SELECT `+function+`(hashtextextended('wbft-analyzer:range:'||current_schema()||':'||$1::bigint::text,0))`, id).Scan(&locked)
	if e != nil || !locked {
		closeConn()
		if e != nil {
			return nil, e
		}
		return nil, ErrDatasetBusy
	}
	if !allowDeleting {
		var exists, deleting bool
		e = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM datasets WHERE id=$1),EXISTS(SELECT 1 FROM dataset_deletions WHERE dataset_id=$1)`, id).Scan(&exists, &deleting)
		if e != nil || !exists || deleting {
			closeConn()
			if e != nil {
				return nil, e
			}
			if deleting {
				return nil, ErrDatasetDeleting
			}
			return nil, ErrNotFound
		}
	}
	var once sync.Once
	return func() { once.Do(closeConn) }, nil
}

// StorageOwner binds a namespace to this database, schema and server endpoint.
// A restored database cannot delete its source database's retained objects.
func (s *Store) StorageOwner(ctx context.Context) (string, error) {
	var database, schema, address string
	var oid uint32
	var port int
	e := s.pool.QueryRow(ctx, `SELECT current_database(),current_schema(),(SELECT oid FROM pg_database WHERE datname=current_database()),COALESCE(inet_server_addr()::text,''),COALESCE(inet_server_port(),0)`).Scan(&database, &schema, &oid, &address, &port)
	if e != nil {
		return "", e
	}
	cfg := s.pool.Config().ConnConfig
	b, _ := json.Marshal([]any{database, schema, oid, address, port, cfg.Host, cfg.Port})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func (s *Store) inputNamespace(ctx context.Context, id int64) (inputs.Namespace, error) {
	var n inputs.Namespace
	e := s.pool.QueryRow(ctx, `SELECT root,token,owner FROM dataset_storage WHERE dataset_id=$1`, id).Scan(&n.Root, &n.Token, &n.Owner)
	if errors.Is(e, pgx.ErrNoRows) {
		return n, ErrNotFound
	}
	return n, e
}

// ClaimInputStorage is called while holding the dataset import lock.
func (s *Store) ClaimInputStorage(ctx context.Context, id int64, directory string) (inputs.Namespace, error) {
	root, e := inputs.PrivateRoot(directory)
	if e != nil {
		return inputs.Namespace{}, e
	}
	owner, e := s.StorageOwner(ctx)
	if e != nil {
		return inputs.Namespace{}, e
	}
	token, e := inputs.NewToken()
	if e != nil {
		return inputs.Namespace{}, e
	}
	_, e = s.pool.Exec(ctx, `INSERT INTO dataset_storage(dataset_id,root,token,owner) VALUES($1,$2,$3,$4) ON CONFLICT(dataset_id) DO NOTHING`, id, root, token, owner)
	if e != nil {
		return inputs.Namespace{}, e
	}
	n, e := s.inputNamespace(ctx, id)
	if e != nil {
		return n, e
	}
	if n.Owner != owner || n.Root != root {
		return n, inputs.ErrOwnership
	}
	return n, n.Ensure()
}
func (s *Store) InputStorageDirectory(ctx context.Context, id int64) (string, error) {
	n, e := s.inputNamespace(ctx, id)
	if e != nil {
		return "", e
	}
	owner, e := s.StorageOwner(ctx)
	if e != nil {
		return "", e
	}
	if owner != n.Owner {
		return "", inputs.ErrOwnership
	}
	if e = n.Verify(); e != nil {
		return "", e
	}
	return n.Directory(), nil
}
func ownedPath(n inputs.Namespace, path, sha string) bool {
	return path == filepath.Join(n.Directory(), sha) && len(sha) == 64
}
