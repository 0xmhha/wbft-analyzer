package store

import (
	"context"
	"encoding/json"
	"errors"
	derived "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/jackc/pgx/v5"
	"time"
)

var ErrPairIndex = errors.New("message pair index is missing or stale; run reindex messages")
var ErrPairWindow = errors.New("message pair window exceeds 100000 rows; narrow the filters")
var ErrPairSource = errors.New("message pairing exceeds one million source records or projected endpoints")

type PairIndex struct {
	Version     string           `json:"version"`
	Records     int64            `json:"records"`
	Pairs       int64            `json:"pairs"`
	Issues      int64            `json:"issues"`
	Status      string           `json:"dataset_status"`
	Diagnostics map[string]int64 `json:"diagnostics"`
	From        *string          `json:"from_t"`
	To          *string          `json:"to_t"`
	Coverage    []PairCoverage   `json:"coverage"`
}

type PairCoverage struct {
	Input                string `json:"input"`
	Kind                 string `json:"kind"`
	GapRecords           int64  `json:"gap_records"`
	SequenceGaps         int64  `json:"sequence_gaps"`
	PartialRuns          *int64 `json:"partial_runs"`
	WallRegressions      *int64 `json:"wall_clock_regressions"`
	MonotonicRegressions *int64 `json:"monotonic_regressions"`
}

// RebuildMessagePairs locks the dataset before reading and replaces the
// projection atomically. Failed imports retain prefix coverage explicitly.
// No time filter is applied before matching: retries outside a displayed
// window must still prevent a false unique match inside it.
func (s *Store) RebuildMessagePairs(ctx context.Context, id int64) (PairIndex, error) {
	out := PairIndex{Version: derived.Version, Diagnostics: map[string]int64{}, Coverage: []PairCoverage{}}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var kind string
		var meta []byte
		var progress int64
		if e := tx.QueryRow(ctx, `SELECT kind,metadata,progress,status FROM datasets WHERE id=$1 FOR UPDATE`, id).Scan(&kind, &meta, &progress, &out.Status); e != nil {
			return e
		}
		if kind != "messages" && kind != "run" {
			return errors.New("dataset has no message evidence")
		}
		var raw struct {
			Clock json.RawMessage `json:"clock"`
		}
		if e := json.Unmarshal(meta, &raw); e != nil {
			return e
		}
		clock := derived.Clock{Model: "unknown"}
		if len(raw.Clock) > 0 && raw.Clock[0] == '"' {
			if e := json.Unmarshal(raw.Clock, &clock.Model); e != nil {
				return e
			}
		} else if len(raw.Clock) > 0 {
			var c source.Clock
			if e := json.Unmarshal(raw.Clock, &c); e != nil {
				return e
			}
			clock.Model = c.Model
			if c.SkewMS != nil {
				clock.SkewMS = *c.SkewMS
			} else if c.Model == "ntp" {
				clock.Model = "unknown"
			}
		}
		// The legacy run manifest has no NTP bound. A model name alone is not
		// enough to manufacture a zero-width uncertainty interval.
		if kind == "run" && clock.Model == "ntp" {
			clock.Model = "unknown"
		}
		coverageQuery := `SELECT input_id,summary->>'kind',stats FROM message_inputs WHERE dataset_id=$1 ORDER BY input_id`
		if kind == "run" {
			coverageQuery = `SELECT input_id,kind,stats FROM log_inputs WHERE dataset_id=$1 ORDER BY input_id`
		}
		coverageRows, e := tx.Query(ctx, coverageQuery, id)
		if e != nil {
			return e
		}
		for coverageRows.Next() {
			var c PairCoverage
			var b []byte
			if e = coverageRows.Scan(&c.Input, &c.Kind, &b); e != nil {
				coverageRows.Close()
				return e
			}
			if kind == "messages" {
				var stats source.Stats
				if e = json.Unmarshal(b, &stats); e != nil {
					coverageRows.Close()
					return e
				}
				c.GapRecords = stats.GapRecords
				c.SequenceGaps = stats.SequenceGaps
				if stats.ClockDiagnostics == "recorded_sequence" {
					partial, regression := stats.PartialRuns, stats.ClockRegressions
					c.PartialRuns = &partial

					c.MonotonicRegressions = &regression
				}
			} else {
				var stats logs.Stats
				if e = json.Unmarshal(b, &stats); e != nil {
					coverageRows.Close()
					return e
				}
				c.SequenceGaps = stats.SequenceGaps
				if stats.Lines > 0 || out.Status == "complete" {
					wall := stats.ClockRegressions
					c.WallRegressions = &wall
					if c.Kind == "events" {
						mono := stats.MonotonicRegressions
						c.MonotonicRegressions = &mono
					}
				}
			}
			out.Coverage = append(out.Coverage, c)
		}
		e = coverageRows.Err()
		coverageRows.Close()
		if e != nil {
			return e
		}
		query := `DECLARE pair_source CURSOR FOR SELECT record FROM message_records WHERE dataset_id=$1 ORDER BY input_id,file,ordinal`
		if kind == "run" {
			query = `DECLARE pair_source CURSOR FOR SELECT event FROM log_events WHERE dataset_id=$1 ORDER BY input_id,line`
		}
		if _, e := tx.Exec(ctx, query, id); e != nil {
			return e
		}
		records := []source.Record{}
		events := []logs.Event{}
		for {
			rows, e := tx.Query(ctx, `FETCH 1000 FROM pair_source`)
			if e != nil {
				return e
			}
			n := 0
			for rows.Next() {
				var b []byte
				if e = rows.Scan(&b); e != nil {
					rows.Close()
					return e
				}
				n++
				out.Records++
				if out.Records > 1000000 {
					rows.Close()
					return ErrPairSource
				}
				if kind == "messages" {
					var x source.Record
					if e = json.Unmarshal(b, &x); e != nil {
						rows.Close()
						return e
					}
					if x.Type == "frame" || x.Type == "gap" {
						records = append(records, x)
					}
				} else {
					var x LogEvent
					if e = json.Unmarshal(b, &x); e != nil {
						rows.Close()
						return e
					}
					r, e := normalized(x)
					if e != nil {
						rows.Close()
						return e
					}
					events = append(events, r)
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			if n < 1000 {
				break
			}
		}
		if out.Records != progress {
			return errors.New("message source count differs from dataset progress")
		}
		projection := derived.ProjectRecords(records)
		if kind == "run" {
			nodes := map[string]bool{}
			sends, outcomes := int64(0), int64(0)
			for _, e := range events {
				nodes[e.Node] = true
				if e.Record.Kind == "SEND" {
					sends++
				}
				if e.Record.Kind == "MSG_OUTCOME" {
					outcomes++
				}
			}
			if sends*int64(len(nodes))+outcomes > 1000000 {
				return ErrPairSource
			}
			projection = derived.ProjectEvents(events)
		}
		if len(projection.Endpoints) > 1000000 {
			return ErrPairSource
		}
		projection.Counts["records"] = out.Records
		out.Diagnostics = projection.Counts
		pairs := derived.PairEndpoints(projection.Endpoints, clock)
		out.Pairs = int64(len(pairs))
		out.Issues = int64(len(projection.Issues))
		for _, table := range []string{"message_pairs", "message_pair_issues"} {
			if _, e := tx.Exec(ctx, `DELETE FROM `+table+` WHERE dataset_id=$1`, id); e != nil {
				return e
			}
		}
		for start := 0; start < len(pairs); start += 1000 {
			end := min(start+1000, len(pairs))
			batch := &pgx.Batch{}
			for _, p := range pairs[start:end] {
				b, e := json.Marshal(p)
				if e != nil {
					return e
				}
				var axis any
				if t, e := time.Parse(time.RFC3339Nano, p.At); e == nil {
					axis = axisNS(t)
					if out.From == nil || beforeWall(p.At, *out.From) {
						x := p.At
						out.From = &x
					}
					if out.To == nil || beforeWall(*out.To, p.At) {
						x := p.At
						out.To = &x
					}
				}
				batch.Queue(`INSERT INTO message_pairs(dataset_id,id,axis_ns,sender,receiver,phase,height,round,strength,path,clock,status,pair) VALUES($1,$2,$3::numeric,$4,$5,$6,nullif($7,'')::numeric,nullif($8,'')::numeric,$9,$10,$11,$12,$13)`, id, p.ID, axis, p.Sender, p.Receiver, p.Phase, p.Height, p.Round, p.Strength, p.Path, p.Clock, p.Status, b)
			}
			if e := tx.SendBatch(ctx, batch).Close(); e != nil {
				return e
			}
		}
		for start := 0; start < len(projection.Issues); start += 1000 {
			end := min(start+1000, len(projection.Issues))
			batch := &pgx.Batch{}
			for i := start; i < end; i++ {
				b, e := json.Marshal(projection.Issues[i])
				if e != nil {
					return e
				}
				batch.Queue(`INSERT INTO message_pair_issues(dataset_id,ordinal,issue) VALUES($1,$2,$3)`, id, i+1, b)
			}
			if e := tx.SendBatch(ctx, batch).Close(); e != nil {
				return e
			}
		}
		info, e := json.Marshal(out)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO message_pair_indexes(dataset_id,version,progress,status,metadata,info) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(dataset_id) DO UPDATE SET version=EXCLUDED.version,progress=EXCLUDED.progress,status=EXCLUDED.status,metadata=EXCLUDED.metadata,info=EXCLUDED.info`, id, derived.Version, progress, out.Status, meta, info)
		return e
	})
	return out, err
}
func beforeWall(a, b string) bool {
	x, _ := time.Parse(time.RFC3339Nano, a)
	y, _ := time.Parse(time.RFC3339Nano, b)
	return x.Before(y)
}

type PairFilter struct {
	From, To                                                                    time.Time
	Sender, Receiver, Node, Phase, Height, Round, Strength, Path, Clock, Status string
}

// MessagePairData reads the index and rows in one repeatable-read snapshot.
// A committed ingest append invalidates the index rather than mixing versions.
func (s *Store) MessagePairData(ctx context.Context, id int64, f PairFilter) (PairIndex, []derived.Pair, error) {
	var index PairIndex
	pairs := []derived.Pair{}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var info []byte
		var ready bool
		e := tx.QueryRow(ctx, `SELECT i.info,coalesce(i.version=$2 AND i.progress=d.progress AND i.status=d.status AND i.metadata=d.metadata,false) FROM datasets d LEFT JOIN message_pair_indexes i ON i.dataset_id=d.id WHERE d.id=$1`, id, derived.Version).Scan(&info, &ready)
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return e
		}
		if !ready {
			return ErrPairIndex
		}
		if e = json.Unmarshal(info, &index); e != nil {
			return e
		}
		var from, to any
		if !f.From.IsZero() {
			from = axisNS(f.From)
		}
		if !f.To.IsZero() {
			to = axisNS(f.To)
		}
		rows, e := tx.Query(ctx, `SELECT pair FROM message_pairs WHERE dataset_id=$1 AND ($2::numeric IS NULL OR axis_ns>=$2) AND ($3::numeric IS NULL OR axis_ns<=$3) AND ($4='' OR sender=$4) AND ($5='' OR receiver=$5) AND ($6='' OR sender=$6 OR receiver=$6) AND ($7='' OR phase=$7) AND (($8='' AND $9='') OR EXISTS(SELECT 1 FROM jsonb_array_elements(pair->'views') v WHERE ($8='' OR v->>'height'=$8) AND ($9='' OR v->>'round'=$9))) AND ($10='' OR strength=$10) AND ($11='' OR path=$11) AND ($12='' OR clock=$12) AND ($13='' OR status=$13) ORDER BY axis_ns NULLS LAST,id LIMIT 100001`, id, from, to, f.Sender, f.Receiver, f.Node, f.Phase, f.Height, f.Round, f.Strength, f.Path, f.Clock, f.Status)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var b []byte
			var p derived.Pair
			if e = rows.Scan(&b); e != nil {
				return e
			}
			if e = json.Unmarshal(b, &p); e != nil {
				return e
			}
			pairs = append(pairs, p)
			if len(pairs) > 100000 {
				return ErrPairWindow
			}
		}
		return rows.Err()
	})
	return index, pairs, err
}

func (s *Store) MessagePairIssues(ctx context.Context, id, after int64, limit int) ([]derived.Issue, error) {
	rows, e := s.pool.Query(ctx, `SELECT issue FROM message_pair_issues WHERE dataset_id=$1 AND ordinal>$2 ORDER BY ordinal LIMIT $3`, id, after, limit)
	if e != nil {
		return nil, e
	}
	return collect(rows, func(r pgx.CollectableRow) (derived.Issue, error) {
		var b []byte
		var x derived.Issue
		e := r.Scan(&b)
		if e == nil {
			e = json.Unmarshal(b, &x)
		}
		return x, e
	})
}
