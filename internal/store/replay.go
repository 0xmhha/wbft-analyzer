package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/derive/replay"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/jackc/pgx/v5"
)

const ReplayVersion = "wbft-visual-replay/2"

var ErrReplayIndex = errors.New("replay index is missing or stale; run reindex replay")
var ErrReplayWindow = errors.New("replay window exceeds 100000 events; narrow the time or node")

func axisNS(t time.Time) string {
	n := new(big.Int).Mul(big.NewInt(t.Unix()), big.NewInt(1000000000))
	return n.Add(n, big.NewInt(int64(t.Nanosecond()))).String()
}
func normalized(x LogEvent) (logs.Event, error) {
	var f map[string]any
	d := json.NewDecoder(bytes.NewReader(x.Fields))
	d.UseNumber()
	if err := d.Decode(&f); err != nil {
		return logs.Event{}, err
	}
	var v *event.View
	if x.Height != "" {
		v = &event.View{Seq: x.Height, Round: x.Round}
	}
	source := x.Source
	if source == "" {
		source = "log"
	}
	return logs.Event{Record: event.Record{Kind: x.Kind, View: v, Src: source, Fields: f}, Mono: x.Mono, Node: x.Node, Input: x.Input, Run: x.Run, Wall: x.Wall, Profile: x.Profile, Level: x.Level, Line: x.Line, ViewInferred: x.ViewInferred}, nil
}

type ReplayIndex struct {
	Records int64  `json:"records"`
	Frames  int64  `json:"frames"`
	Version string `json:"version"`
}

// RebuildReplay holds the dataset row lock. Concurrent ingestion cannot commit
// its progress until this consistent projection has been saved atomically.
// Rows stream by node and precise wall axis; only one node's state is retained.
func (s *Store) RebuildReplay(ctx context.Context, dataset int64) (ReplayIndex, error) {
	out := ReplayIndex{Version: ReplayVersion}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var progress int64
		var kind string
		if err := tx.QueryRow(ctx, `SELECT progress,kind FROM datasets WHERE id=$1 FOR UPDATE`, dataset).Scan(&progress, &kind); err != nil {
			return err
		}
		if kind != "run" {
			return errors.New("dataset has no replay events")
		}
		if _, err := tx.Exec(ctx, `DELETE FROM replay_keyframes WHERE dataset_id=$1`, dataset); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DECLARE replay_source CURSOR FOR SELECT event FROM log_events WHERE dataset_id=$1 ORDER BY node,axis_ns,input_id,line`, dataset); err != nil {
			return err
		}
		state := replay.New("")
		count := int64(0)
		for {
			rows, err := tx.Query(ctx, `FETCH 1000 FROM replay_source`)
			if err != nil {
				return err
			}
			pending := [][]any{}
			fetched := 0
			for rows.Next() {
				fetched++
				var b []byte
				var x LogEvent
				if err = rows.Scan(&b); err != nil {
					rows.Close()
					return err
				}
				if err = json.Unmarshal(b, &x); err != nil {
					rows.Close()
					return err
				}
				e, err := normalized(x)
				if err != nil {
					rows.Close()
					return err
				}
				if state.Node != e.Node {
					state = replay.New(e.Node)
					count = 0
				}
				old := ""
				if state.View != nil {
					old = state.View.Seq
				}
				replay.Apply(&state, e)
				count++
				out.Records++
				changed := state.View != nil && state.View.Seq != old
				if count == 1 || count%1024 == 0 || changed || e.Record.Kind == event.NodeStart || e.Record.Kind == event.NodeStop || e.Record.Kind == event.EngineStart || e.Record.Kind == event.EngineStop {
					frame := replay.Keyframe{At: e.Wall, Input: e.Input, Line: e.Line, Folded: count, State: state}
					raw, err := json.Marshal(frame)
					if err != nil {
						rows.Close()
						return err
					}
					at, _ := time.Parse(time.RFC3339Nano, e.Wall)
					pending = append(pending, []any{dataset, e.Node, axisNS(at), e.Input, e.Line, raw})
					out.Frames++
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			batch := &pgx.Batch{}
			for _, row := range pending {
				batch.Queue(`INSERT INTO replay_keyframes(dataset_id,node,axis_ns,input_id,line,frame) VALUES($1,$2,$3::numeric,$4,$5,$6)`, row...)
			}
			result := tx.SendBatch(ctx, batch)
			if err = result.Close(); err != nil {
				return err
			}
			if fetched < 1000 {
				break
			}
		}
		if out.Records != progress {
			return errors.New("source count differs from dataset progress")
		}
		_, err := tx.Exec(ctx, `INSERT INTO replay_indexes(dataset_id,progress,version,records,frames) VALUES($1,$2,$3,$4,$5) ON CONFLICT(dataset_id) DO UPDATE SET progress=EXCLUDED.progress,version=EXCLUDED.version,records=EXCLUDED.records,frames=EXCLUDED.frames`, dataset, progress, ReplayVersion, out.Records, out.Frames)
		return err
	})
	return out, err
}
func (s *Store) replayReady(ctx context.Context, dataset int64) (int64, error) {
	var ready bool
	var progress int64
	err := s.pool.QueryRow(ctx, `SELECT coalesce((SELECT i.version=$2 AND i.progress=d.progress FROM replay_indexes i WHERE i.dataset_id=d.id),false),d.progress FROM datasets d WHERE d.id=$1`, dataset, ReplayVersion).Scan(&ready, &progress)
	if err != nil {
		return 0, err
	}
	if !ready {
		return 0, ErrReplayIndex
	}
	return progress, nil
}

type ReplayState struct {
	State   replay.State     `json:"state"`
	Frame   *replay.Keyframe `json:"keyframe"`
	Tail    int64            `json:"tail_records"`
	Version string           `json:"version"`
}

func (s *Store) ReplayState(ctx context.Context, dataset int64, node string, target time.Time) (ReplayState, error) {
	out := ReplayState{State: replay.New(node), Version: ReplayVersion}
	revision, err := s.replayReady(ctx, dataset)
	if err != nil {
		return out, err
	}
	var raw []byte
	err = s.pool.QueryRow(ctx, `SELECT frame FROM replay_keyframes WHERE dataset_id=$1 AND node=$2 AND axis_ns<=$3::numeric ORDER BY axis_ns DESC,input_id DESC,line DESC LIMIT 1`, dataset, node, axisNS(target)).Scan(&raw)
	var from any
	input := ""
	line := int64(0)
	if err == nil {
		out.Frame = &replay.Keyframe{}
		if err = json.Unmarshal(raw, out.Frame); err != nil {
			return out, err
		}
		out.State = replay.Clone(out.Frame.State)
		at, _ := time.Parse(time.RFC3339Nano, out.Frame.At)
		from = axisNS(at)
		input = out.Frame.Input
		line = out.Frame.Line
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	rows, err := s.pool.Query(ctx, `SELECT event FROM log_events WHERE dataset_id=$1 AND node=$2 AND axis_ns<=$3::numeric AND ($4::numeric IS NULL OR (axis_ns,input_id,line)>($4::numeric,$5,$6)) ORDER BY axis_ns,input_id,line LIMIT 1025`, dataset, node, axisNS(target), from, input, line)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		var x LogEvent
		if err = rows.Scan(&b); err != nil {
			return out, err
		}
		if err = json.Unmarshal(b, &x); err != nil {
			return out, err
		}
		e, err := normalized(x)
		if err != nil {
			return out, err
		}
		replay.Apply(&out.State, e)
		out.Tail++
		if out.Tail > 1024 {
			return out, fmt.Errorf("%w: tail bound violated", ErrReplayIndex)
		}
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	latest, err := s.replayReady(ctx, dataset)
	if err != nil {
		return out, err
	}
	if latest != revision {
		return out, ErrReplayIndex
	}
	return out, nil
}

type ReplayNode struct {
	Node            string      `json:"node"`
	Initial         ReplayState `json:"initial"`
	Levels          []string    `json:"levels"`
	SequenceGaps    int64       `json:"sequence_gaps"`
	MonoRegressions int64       `json:"monotonic_regressions"`
	WallRegressions int64       `json:"wall_regressions"`
}
type ReplayWindow struct {
	Events  []LogEvent   `json:"events"`
	Nodes   []ReplayNode `json:"nodes"`
	Version string       `json:"version"`
}

func (s *Store) ReplayWindow(ctx context.Context, dataset int64, from, to time.Time, node string, endInput string, endLine int64) (ReplayWindow, error) {
	out := ReplayWindow{Events: []LogEvent{}, Nodes: []ReplayNode{}, Version: ReplayVersion}
	revision, err := s.replayReady(ctx, dataset)
	if err != nil {
		return out, err
	}
	inputs, err := s.LogInputs(ctx, dataset)
	if err != nil {
		return out, err
	}
	seen := map[string]bool{}
	for _, in := range inputs {
		if node != "" && node != in.Node {
			continue
		}
		if seen[in.Node] {
			continue
		}
		seen[in.Node] = true
		initial, err := s.ReplayState(ctx, dataset, in.Node, from.Add(-time.Nanosecond))
		if err != nil {
			return out, err
		}
		out.Nodes = append(out.Nodes, ReplayNode{Node: in.Node, Initial: initial, Levels: []string{}})
	}
	rows, err := s.pool.Query(ctx, `SELECT event FROM log_events WHERE dataset_id=$1 AND axis_ns BETWEEN $2::numeric AND $3::numeric AND ($4='' OR node=$4) AND ($5='' OR axis_ns<$3::numeric OR (input_id,line)<=($5,$6)) ORDER BY axis_ns,input_id,line LIMIT 100001`, dataset, axisNS(from), axisNS(to), node, endInput, endLine)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	levels := map[string]map[string]bool{}
	for rows.Next() {
		var b []byte
		var x LogEvent
		if err = rows.Scan(&b); err != nil {
			return out, err
		}
		if err = json.Unmarshal(b, &x); err != nil {
			return out, err
		}
		out.Events = append(out.Events, x)
		if len(out.Events) > 100000 {
			return out, ErrReplayWindow
		}
		if levels[x.Node] == nil {
			levels[x.Node] = map[string]bool{}
		}
		level := "log-" + x.Level
		if x.Source == "event" {
			level = "events"
		}
		levels[x.Node][level] = true
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	for i := range out.Nodes {
		n := &out.Nodes[i]
		for _, level := range []string{"events", "log-info", "log-debug", "log-trace", "log-warn", "log-error"} {
			if levels[n.Node][level] {
				n.Levels = append(n.Levels, level)
			}
		}
		for _, in := range inputs {
			if in.Node == n.Node {
				n.SequenceGaps += in.Stats.SequenceGaps
				n.MonoRegressions += in.Stats.MonotonicRegressions
				n.WallRegressions += in.Stats.ClockRegressions
			}
		}
	}
	latest, err := s.replayReady(ctx, dataset)
	if err != nil {
		return out, err
	}
	if latest != revision {
		return out, ErrReplayIndex
	}
	return out, nil
}
