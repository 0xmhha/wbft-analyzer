package store

import (
	"context"
	"errors"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/jackc/pgx/v5"
)

func (s *Store) PutInputFiles(ctx context.Context, dataset int64, input string, files []messages.ArchivedFile) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, f := range files {
			tag, err := tx.Exec(ctx, `INSERT INTO input_files(dataset_id,input_id,name,sha256,bytes,path) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(dataset_id,input_id,name) DO UPDATE SET path=input_files.path WHERE input_files.sha256=EXCLUDED.sha256 AND input_files.bytes=EXCLUDED.bytes AND input_files.path=EXCLUDED.path`, dataset, input, f.Name, f.SHA256, f.Bytes, f.Path)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return errors.New("input storage reference conflict")
			}
		}
		return nil
	})
}

// InputFiles is an internal replay input lookup; paths are not served by HTTP.
func (s *Store) InputFiles(ctx context.Context, dataset int64, input string) ([]messages.ArchivedFile, error) {
	rows, err := s.pool.Query(ctx, `SELECT name,sha256,bytes,path FROM input_files WHERE dataset_id=$1 AND input_id=$2 ORDER BY name`, dataset, input)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.CollectableRow) (messages.ArchivedFile, error) {
		var f messages.ArchivedFile
		err := r.Scan(&f.Name, &f.SHA256, &f.Bytes, &f.Path)
		return f, err
	})
}
