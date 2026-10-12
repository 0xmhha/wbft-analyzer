package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/jackc/pgx/v5"
)

type MessageInput struct {
	Summary messages.Summary `json:"summary"`
	Stats   messages.Stats   `json:"stats"`
}

func (s *Store) BeginMessages(ctx context.Context, k NetworkKey, name string, metadata json.RawMessage) (Dataset, func(), error) {
	return s.beginDataset(ctx, k, name, "messages", metadata)
}
func (s *Store) PutMessageInput(ctx context.Context, id int64, sum messages.Summary) error {
	raw, e := json.Marshal(sum)
	if e != nil {
		return e
	}
	tag, e := s.pool.Exec(ctx, `INSERT INTO message_inputs(dataset_id,input_id,node,summary) VALUES($1,$2,$3,$4) ON CONFLICT(dataset_id,input_id) DO UPDATE SET summary=message_inputs.summary WHERE message_inputs.summary=EXCLUDED.summary`, id, sum.ID, sum.Node, raw)
	if e == nil && tag.RowsAffected() != 1 {
		return errors.New("message input conflict")
	}
	return e
}
func (s *Store) FinishMessageInput(ctx context.Context, id int64, input string, stats messages.Stats) error {
	raw, e := json.Marshal(stats)
	if e != nil {
		return e
	}
	_, e = s.pool.Exec(ctx, `UPDATE message_inputs SET stats=$3 WHERE dataset_id=$1 AND input_id=$2`, id, input, raw)
	return e
}
func (s *Store) PutMessageRecords(ctx context.Context, id int64, xs []messages.Record, progress int64) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, r := range xs {
			// Record is a closed metadata type; there is no map accepting arbitrary
			// payload, raw input, remote address, configuration, reason or error text.
			raw, e := json.Marshal(r)
			if e != nil {
				return e
			}
			b.Queue(`INSERT INTO message_records(dataset_id,input_id,file,ordinal,node,run,seq,type,height,round,record) VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8,nullif($9,'')::numeric,nullif($10,'')::numeric,$11) ON CONFLICT(dataset_id,input_id,file,ordinal) DO UPDATE SET record=message_records.record WHERE message_records.record=EXCLUDED.record`, id, r.Input, r.File, r.Ordinal, r.Node, r.Run, r.Seq, r.Type, r.Height, r.Round, raw)
		}
		res := tx.SendBatch(ctx, b)
		for range xs {
			tag, e := res.Exec()
			if e != nil {
				_ = res.Close()
				return e
			}
			if tag.RowsAffected() != 1 {
				_ = res.Close()
				return errors.New("message source conflict")
			}
		}
		if e := res.Close(); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `UPDATE datasets SET progress=$2,updated_at=now() WHERE id=$1`, id, progress)
		return e
	})
}
func (s *Store) MessageInputs(ctx context.Context, id int64) ([]MessageInput, error) {
	rows, e := s.pool.Query(ctx, `SELECT summary,stats FROM message_inputs WHERE dataset_id=$1 ORDER BY input_id`, id)
	if e != nil {
		return nil, e
	}
	return collect(rows, func(r pgx.CollectableRow) (MessageInput, error) {
		var x MessageInput
		var a, b []byte
		e := r.Scan(&a, &b)
		if e == nil {
			e = json.Unmarshal(a, &x.Summary)
		}
		if e == nil {
			e = json.Unmarshal(b, &x.Stats)
		}
		return x, e
	})
}

type MessageFilter struct {
	Input, Type, Node, Height, Round, Phase, AfterInput, AfterFile string
	AfterOrdinal                                                   int64
	Limit                                                          int
}

func (s *Store) MessageRecords(ctx context.Context, id int64, f MessageFilter) ([]messages.Record, error) {
	rows, e := s.pool.Query(ctx, `SELECT record FROM message_records WHERE dataset_id=$1 AND ($2='' OR input_id=$2) AND ($3='' OR type=$3) AND ($4='' OR node=$4) AND ($5='' OR height=nullif($5,'')::numeric) AND ($6='' OR round=nullif($6,'')::numeric) AND ($11='' OR record->>'phase'=$11) AND (input_id,file,ordinal)>($7,$8,$9) ORDER BY input_id,file,ordinal LIMIT $10`, id, f.Input, f.Type, f.Node, f.Height, f.Round, f.AfterInput, f.AfterFile, f.AfterOrdinal, f.Limit, f.Phase)
	if e != nil {
		return nil, e
	}
	return collect(rows, func(r pgx.CollectableRow) (messages.Record, error) {
		var x messages.Record
		var raw []byte
		e := r.Scan(&raw)
		if e == nil {
			e = json.Unmarshal(raw, &x)
		}
		return x, e
	})
}
