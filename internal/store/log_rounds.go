package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/derive/rounds"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

var ErrEventWindowTooLarge = errors.New("round analysis window exceeds 100000 relevant events")

func (s *Store) LogRounds(ctx context.Context, dataset int64, from, to time.Time) (rounds.Summary, error) {
	rows, err := s.pool.Query(ctx, `SELECT event FROM log_events WHERE dataset_id=$1 AND t_wall BETWEEN $2 AND $3 AND kind IN ('ROUND_ENTER','NEW_HEAD','TIMER_FIRE','QUORUM','ENGINE_START','ENGINE_STOP') ORDER BY input_id,line LIMIT 100001`, dataset, from, to)
	if err != nil {
		return rounds.Summary{}, err
	}
	defer rows.Close()
	events := []logs.Event{}
	for rows.Next() {
		var raw []byte
		var x LogEvent
		if err := rows.Scan(&raw); err != nil {
			return rounds.Summary{}, err
		}
		if err := json.Unmarshal(raw, &x); err != nil {
			return rounds.Summary{}, err
		}
		var fields map[string]any
		d := json.NewDecoder(bytes.NewReader(x.Fields))
		d.UseNumber()
		if err := d.Decode(&fields); err != nil {
			return rounds.Summary{}, err
		}
		var v *event.View
		if x.Height != "" {
			v = &event.View{Seq: x.Height, Round: x.Round}
		}
		events = append(events, logs.Event{Record: event.Record{Kind: x.Kind, View: v, Src: "log", Fields: fields}, Node: x.Node, Input: x.Input, Run: x.Run, Wall: x.Wall, Level: x.Level, Profile: x.Profile, Line: x.Line, ViewInferred: x.ViewInferred})
		if len(events) > 100000 {
			return rounds.Summary{}, ErrEventWindowTooLarge
		}
	}
	if err := rows.Err(); err != nil {
		return rounds.Summary{}, err
	}
	return rounds.Derive(events), nil
}
