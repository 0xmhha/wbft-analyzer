package store

import (
	"context"
	"encoding/json"
	"errors"
	derived "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/jackc/pgx/v5"
)

type IssueFilter struct {
	Node, Reason  string
	SourceDataset int64
}
type MessageIssue struct {
	Ordinal int64         `json:"ordinal"`
	Issue   derived.Issue `json:"issue"`
}

// MessageIssueData reads readiness, source filters, counts and one bounded page
// from a single snapshot. A changed companion invalidates issues as well as pairs.
func (s *Store) MessageIssueData(ctx context.Context, id int64, f IssueFilter, after int64, limit int) (PairIndex, []MessageIssue, int64, error) {
	var index PairIndex
	out := []MessageIssue{}
	var total int64
	if after < 0 || limit < 1 || limit > 1000 {
		return index, out, 0, errors.New("invalid issue page")
	}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var e error
		index, e = readPairIndex(ctx, tx, id)
		if e != nil {
			return e
		}
		if index.Snapshot == "" {
			return ErrPairIndex
		}
		predicate := `dataset_id=$1 AND ($2='' OR issue->'source'->>'node'=$2) AND ($3='' OR issue->>'reason'=$3) AND ($4::bigint=0 OR coalesce((issue->'source'->>'dataset_id')::bigint,$1)=$4)`
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM message_pair_issues WHERE `+predicate, id, f.Node, f.Reason, f.SourceDataset).Scan(&total); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT ordinal,issue FROM message_pair_issues WHERE `+predicate+` AND ordinal>$5 ORDER BY ordinal LIMIT $6`, id, f.Node, f.Reason, f.SourceDataset, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var x MessageIssue
			var b []byte
			if e = rows.Scan(&x.Ordinal, &b); e != nil {
				return e
			}
			if e = json.Unmarshal(b, &x.Issue); e != nil {
				return e
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	return index, out, total, err
}
