package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrFollowCursor = errors.New("follow cursor or completed batch evidence changed")

type FollowCursor struct {
	DatasetID  int64  `json:"dataset_id"`
	Next       string `json:"next_index"`
	ParentHash string `json:"parent_hash"`
}

type FollowBatch struct {
	From                string `json:"from_index"`
	To                  string `json:"to_index"`
	HeadersDataset      int64  `json:"headers_dataset"`
	ObservationsDataset int64  `json:"observations_dataset"`
}
type FollowState struct {
	Cursor       FollowCursor  `json:"cursor"`
	Status       string        `json:"status"`
	Captured     int64         `json:"captured_heights"`
	TotalBatches int64         `json:"total_batches"`
	Latest       []FollowBatch `json:"latest_batches"`
	UpdatedAt    time.Time     `json:"last_commit_at"`
	LastIssue    string        `json:"last_issue"`
}

// FollowState reads one consistent snapshot; its preview is limited to 100
// completed batches. Companion dataset IDs identify the original captures.
func (s *Store) FollowState(ctx context.Context, id int64) (out FollowState, e error) {
	out.Latest = []FollowBatch{}
	out.Cursor.DatasetID = id
	e = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT c.next_index::text,c.parent_hash,d.status,d.progress,c.updated_at,d.error FROM follow_cursors c JOIN datasets d ON d.id=c.dataset_id WHERE d.id=$1`, id).Scan(&out.Cursor.Next, &out.Cursor.ParentHash, &out.Status, &out.Captured, &out.UpdatedAt, &out.LastIssue); e != nil {
			return e
		}
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM follow_batches WHERE dataset_id=$1`, id).Scan(&out.TotalBatches); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT from_index::text,to_index::text,headers_dataset,observations_dataset FROM follow_batches WHERE dataset_id=$1 ORDER BY from_index DESC LIMIT 100`, id)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var b FollowBatch
			if e = rows.Scan(&b.From, &b.To, &b.HeadersDataset, &b.ObservationsDataset); e != nil {
				return e
			}
			out.Latest = append(out.Latest, b)
		}
		return rows.Err()
	})
	return
}

func (s *Store) BeginFollow(ctx context.Context, k NetworkKey, name string, metadata json.RawMessage, from uint64, parent string) (Dataset, func(), error) {
	d, release, e := s.beginDataset(ctx, k, name, "follow", metadata)
	if e != nil {
		return d, nil, e
	}
	_, e = s.pool.Exec(ctx, `INSERT INTO follow_cursors(dataset_id,next_index,parent_hash) VALUES($1,$2::numeric,$3) ON CONFLICT(dataset_id) DO NOTHING`, d.ID, strconv.FormatUint(from, 10), parent)
	if e != nil {
		release()
		return d, nil, e
	}
	return d, release, nil
}

func (s *Store) FollowCursor(ctx context.Context, id int64) (c FollowCursor, e error) {
	c.DatasetID = id
	e = s.pool.QueryRow(ctx, `SELECT next_index::text,parent_hash FROM follow_cursors WHERE dataset_id=$1`, id).Scan(&c.Next, &c.ParentHash)
	return
}

// CommitFollow links completed immutable captures and advances the cursor in
// one transaction. A deleted child or a competing cursor cannot prove progress.
func (s *Store) CommitFollow(ctx context.Context, id int64, from, to uint64, parent, end string, headersID, observationsID int64) error {
	if to < from || to == ^uint64(0) || to-from >= 100 {
		return ErrFollowCursor
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var next, old string
		if e := tx.QueryRow(ctx, `SELECT next_index::text,parent_hash FROM follow_cursors WHERE dataset_id=$1 FOR UPDATE`, id).Scan(&next, &old); e != nil {
			return e
		}
		if next != strconv.FormatUint(from, 10) || old != parent {
			return ErrFollowCursor
		}
		var valid bool
		e := tx.QueryRow(ctx, `SELECT h.status='complete' AND o.status='complete' AND h.kind='range' AND o.kind='observations' AND h.network_id=f.network_id AND o.network_id=f.network_id
   AND (h.metadata->>'from')=$4 AND (h.metadata->>'to')=$5
   AND EXISTS(SELECT 1 FROM heights x WHERE x.network_id=f.network_id AND x.index_=$5::numeric AND x.hash=$6)
   AND EXISTS(SELECT 1 FROM heights x WHERE x.network_id=f.network_id AND x.index_=$4::numeric AND x.fact->>'parent_hash'=$7)
   AND EXISTS(SELECT 1 FROM observation_captures c WHERE c.dataset_id=o.id AND c.info->'comparison'->>'status'='match' AND c.node=f.metadata->>'address')
   AND (SELECT count(*) FROM observation_participation p WHERE p.dataset_id=o.id)=($5::numeric-$4::numeric+1)
   AND NOT EXISTS(SELECT 1 FROM observation_participation p WHERE p.dataset_id=o.id AND (p.row_->>'gap')::boolean)
   AND NOT EXISTS(SELECT 1 FROM observation_participation p WHERE p.dataset_id=o.id AND NOT EXISTS(SELECT 1 FROM heights x WHERE x.network_id=f.network_id AND x.index_ BETWEEN $4::numeric AND $5::numeric AND x.fact->>'number'=p.height::text AND x.hash=p.row_->>'hash'))
   FROM datasets f,datasets h,datasets o WHERE f.id=$1 AND h.id=$2 AND o.id=$3`, id, headersID, observationsID, strconv.FormatUint(from, 10), strconv.FormatUint(to, 10), end, parent).Scan(&valid)
		if e != nil {
			return e
		}
		if !valid {
			return ErrFollowCursor
		}
		if _, e = tx.Exec(ctx, `INSERT INTO follow_batches(dataset_id,from_index,to_index,headers_dataset,observations_dataset) VALUES($1,$2::numeric,$3::numeric,$4,$5)`, id, next, strconv.FormatUint(to, 10), headersID, observationsID); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE follow_cursors SET next_index=$2::numeric,parent_hash=$3,updated_at=now() WHERE dataset_id=$1`, id, strconv.FormatUint(to+1, 10), end); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE datasets SET progress=progress+$2,updated_at=now(),error='' WHERE id=$1`, id, int64(to-from)+1)
		return e
	})
}

func (s *Store) StopFollow(ctx context.Context, id int64) error {
	_, e := s.pool.Exec(ctx, `UPDATE datasets SET status='ready',updated_at=now() WHERE id=$1 AND kind='follow'`, id)
	return e
}

func (s *Store) FollowIssue(ctx context.Context, id int64, issue string) error {
	switch issue {
	case "collection_retry", "participation_incomplete", "identity_conflict", "stored_cursor_conflict":
	default:
		return errors.New("invalid follow issue category")
	}
	_, e := s.pool.Exec(ctx, `UPDATE datasets SET error=$2,updated_at=now() WHERE id=$1 AND kind='follow'`, id, issue)
	return e
}
