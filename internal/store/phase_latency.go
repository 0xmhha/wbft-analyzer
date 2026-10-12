package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/0xmhha/wbft-analyzer/internal/derive/latency"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

var ErrPhaseWindowTooLarge = errors.New("phase window and its context exceed 100000 relevant records; narrow the window or node filter")

// PhaseSamples includes context back to the latest round/engine boundary of
// each input/run before the requested window. Analysis still selects samples
// by their endpoint time. No whole-dataset scan or missing-as-zero shortcut.
func (s *Store) PhaseSamples(ctx context.Context, dataset int64, f latency.Filter) ([]latency.Sample, error) {
	rows, err := s.pool.Query(ctx, `WITH firsts AS (
 SELECT input_id,run,min(line) first_line FROM log_events WHERE dataset_id=$1 AND t_wall BETWEEN date_trunc('microseconds',$2::timestamptz) AND $3 AND ($4='' OR node=$4) GROUP BY input_id,run
 ), anchors AS (
 SELECT a.input_id,a.run,coalesce((SELECT max(b.line) FROM log_events b WHERE b.dataset_id=$1 AND b.input_id=a.input_id AND b.run=a.run AND b.line<=a.first_line AND b.kind IN ('ROUND_ENTER','ENGINE_START','ENGINE_STOP')),a.first_line) start_line FROM firsts a
 ) SELECT e.event FROM log_events e JOIN anchors a ON a.input_id=e.input_id AND a.run=e.run WHERE e.dataset_id=$1 AND e.line>=a.start_line AND e.t_wall<=$3 AND e.kind IN ('ROUND_ENTER','PREPREPARE_ACCEPT','QUORUM','FINALIZE_HANDOVER','NEW_HEAD','ENGINE_START','ENGINE_STOP') ORDER BY e.input_id,e.line LIMIT 100001`, dataset, f.From, f.To, f.Node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []logs.Event{}
	for rows.Next() {
		var b []byte
		var x LogEvent
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &x); err != nil {
			return nil, err
		}
		var fields map[string]any
		d := json.NewDecoder(bytes.NewReader(x.Fields))
		d.UseNumber()
		if err := d.Decode(&fields); err != nil {
			return nil, err
		}
		var v *event.View
		if x.Height != "" {
			v = &event.View{Seq: x.Height, Round: x.Round}
		}
		records = append(records, logs.Event{Record: event.Record{Kind: x.Kind, View: v, Src: "log", Fields: fields}, Mono: x.Mono, Node: x.Node, Input: x.Input, Run: x.Run, Wall: x.Wall, Profile: x.Profile, Level: x.Level, Line: x.Line, ViewInferred: x.ViewInferred})
		if len(records) > 100000 {
			return nil, ErrPhaseWindowTooLarge
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return latency.Derive(records, f), nil
}
