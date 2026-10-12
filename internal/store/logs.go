package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/jackc/pgx/v5"
)

type LogEvent struct {
	Input        string          `json:"input"`
	Line         int64           `json:"line"`
	Node         string          `json:"node"`
	Run          string          `json:"run"`
	Wall         string          `json:"t_wall"`
	Kind         event.Kind      `json:"kind"`
	Height       string          `json:"height"`
	Round        string          `json:"round"`
	Level        string          `json:"level"`
	Profile      string          `json:"profile"`
	ViewInferred bool            `json:"view_inferred"`
	Fields       json.RawMessage `json:"fields"`
}
type LogInput struct {
	ID            string     `json:"id"`
	Node          string     `json:"node"`
	Profile       string     `json:"profile"`
	ProfileSHA256 string     `json:"profile_sha256"`
	SHA256        string     `json:"sha256"`
	Bytes         int64      `json:"bytes"`
	Stats         logs.Stats `json:"stats"`
}

func (s *Store) PutLogInput(ctx context.Context, dataset int64, in logs.InputSummary) error {
	tag, err := s.pool.Exec(ctx, `INSERT INTO log_inputs(dataset_id,input_id,node,profile,profile_sha256,sha256,bytes) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(dataset_id,input_id) DO UPDATE SET input_id=log_inputs.input_id WHERE log_inputs.node=EXCLUDED.node AND log_inputs.profile=EXCLUDED.profile AND log_inputs.profile_sha256=EXCLUDED.profile_sha256 AND log_inputs.sha256=EXCLUDED.sha256 AND log_inputs.bytes=EXCLUDED.bytes`, dataset, in.ID, in.Node, in.Profile, in.ProfileSHA256, in.SHA256, in.Bytes)
	if err == nil && tag.RowsAffected() != 1 {
		err = errors.New("log input conflict")
	}
	return err
}
func (s *Store) FinishLogInput(ctx context.Context, dataset int64, id string, stats logs.Stats) error {
	b, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE log_inputs SET stats=$3 WHERE dataset_id=$1 AND input_id=$2`, dataset, id, b)
	return err
}
func (s *Store) PutLogEvents(ctx context.Context, dataset int64, events []logs.Event, progress int64) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		batch := &pgx.Batch{}
		for _, e := range events {
			// Sanitize once more at the persistence boundary; API clients and future
			// event sources cannot bypass the metadata allowlist.
			raw, err := json.Marshal(e.Record.Fields)
			if err != nil {
				return err
			}
			var m map[string]json.RawMessage
			if err = json.Unmarshal(raw, &m); err != nil {
				return err
			}
			fields, err := json.Marshal(logs.Metadata(m))
			if err != nil {
				return err
			}
			x := LogEvent{Input: e.Input, Line: e.Line, Node: e.Node, Run: e.Run, Wall: e.Wall, Kind: e.Record.Kind, Level: e.Level, Profile: e.Profile, ViewInferred: e.ViewInferred, Fields: fields}
			var height, round any
			if e.Record.View != nil {
				x.Height = e.Record.View.Seq
				x.Round = e.Record.View.Round
				if x.Height != "" {
					height = x.Height
				}
				if x.Round != "" {
					round = x.Round
				}
			}
			b, err := json.Marshal(x)
			if err != nil {
				return err
			}
			wall, err := time.Parse(time.RFC3339Nano, e.Wall)
			if err != nil {
				return err
			}
			batch.Queue(`INSERT INTO log_events(dataset_id,input_id,line,node,run,t_wall,kind,height,round,event) VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10) ON CONFLICT(dataset_id,input_id,line) DO UPDATE SET event=log_events.event WHERE log_events.event=EXCLUDED.event`, dataset, e.Input, e.Line, e.Node, e.Run, wall.Truncate(time.Microsecond), e.Record.Kind, height, round, b)
		}
		results := tx.SendBatch(ctx, batch)
		for range events {
			tag, err := results.Exec()
			if err != nil {
				_ = results.Close()
				return err
			}
			if tag.RowsAffected() != 1 {
				_ = results.Close()
				return errors.New("log event source conflict")
			}
		}
		if err := results.Close(); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE datasets SET progress=$2,updated_at=now() WHERE id=$1`, dataset, progress)
		return err
	})
}
func (s *Store) LogInputs(ctx context.Context, dataset int64) ([]LogInput, error) {
	rows, err := s.pool.Query(ctx, `SELECT input_id,node,profile,profile_sha256,sha256,bytes,stats FROM log_inputs WHERE dataset_id=$1 ORDER BY input_id`, dataset)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.CollectableRow) (LogInput, error) {
		var in LogInput
		var raw []byte
		err := r.Scan(&in.ID, &in.Node, &in.Profile, &in.ProfileSHA256, &in.SHA256, &in.Bytes, &raw)
		if err == nil {
			err = json.Unmarshal(raw, &in.Stats)
		}
		return in, err
	})
}

// EventFilter is a bounded wall-clock window. The cursor binds all filters in
// the API layer; ordering uses (wall,input,line), never a large OFFSET.
type EventFilter struct {
	From, To                         time.Time
	Node, Kind, Phase, Height, Round string
	CursorWall                       *time.Time
	CursorInput                      string
	CursorLine                       int64
	Limit                            int
}

func (s *Store) LogEvents(ctx context.Context, dataset int64, f EventFilter) ([]LogEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT event FROM log_events WHERE dataset_id=$1 AND t_wall BETWEEN $2 AND $3 AND ($4='' OR node=$4) AND ($5='' OR kind=$5) AND ($6='' OR event->'fields'->>'phase'=$6) AND ($7='' OR height=nullif($7,'')::numeric) AND ($8='' OR round=nullif($8,'')::numeric) AND ($9::timestamptz IS NULL OR (t_wall,input_id,line)>($9,$10,$11)) ORDER BY t_wall,input_id,line LIMIT $12`, dataset, f.From, f.To, f.Node, f.Kind, f.Phase, f.Height, f.Round, f.CursorWall, f.CursorInput, f.CursorLine, f.Limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.CollectableRow) (LogEvent, error) {
		var x LogEvent
		var raw []byte
		err := r.Scan(&raw)
		if err == nil {
			err = json.Unmarshal(raw, &x)
		}
		return x, err
	})
}

type EventBounds struct {
	From  *time.Time `json:"from_t"`
	To    *time.Time `json:"to_t"`
	Count int64      `json:"count"`
}

func (s *Store) LogBounds(ctx context.Context, dataset int64) (EventBounds, error) {
	var b EventBounds
	err := s.pool.QueryRow(ctx, `SELECT min(t_wall),max(t_wall),count(*) FROM log_events WHERE dataset_id=$1`, dataset).Scan(&b.From, &b.To, &b.Count)
	return b, err
}

func LogInputOf(summary logs.InputSummary, stats logs.Stats) LogInput {
	return LogInput{ID: summary.ID, Node: summary.Node, Profile: summary.Profile, ProfileSHA256: summary.ProfileSHA256, SHA256: summary.SHA256, Bytes: summary.Bytes, Stats: stats}
}

func (s *Store) LogEvent(ctx context.Context, dataset int64, input string, line int64) (LogEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT event FROM log_events WHERE dataset_id=$1 AND input_id=$2 AND line=$3`, dataset, input, line)
	if err != nil {
		return LogEvent{}, err
	}
	return one(rows, func(r pgx.CollectableRow) (LogEvent, error) {
		var x LogEvent
		var raw []byte
		err := r.Scan(&raw)
		if err == nil {
			err = json.Unmarshal(raw, &x)
		}
		return x, err
	})
}
