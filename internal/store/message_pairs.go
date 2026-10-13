package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	derived "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/jackc/pgx/v5"
	"sort"
	"time"
)

var ErrPairIndex = errors.New("message pair index is missing or stale; run reindex messages")
var ErrPairWindow = errors.New("message pair window exceeds 100000 rows; narrow the filters")
var ErrPairSource = errors.New("message pairing exceeds one million source records or projected endpoints")

type PairIndex struct {
	LegacyAssociations []derived.LegacyAssociationProof `json:"legacy_associations,omitempty"`
	Snapshot           string                           `json:"snapshot"`
	EventDataset       int64                            `json:"event_dataset,omitempty"`
	Association        *derived.AssociationProof        `json:"association,omitempty"`
	Version            string                           `json:"version"`
	Records            int64                            `json:"records"`
	Pairs              int64                            `json:"pairs"`
	Issues             int64                            `json:"issues"`
	Status             string                           `json:"dataset_status"`
	Diagnostics        map[string]int64                 `json:"diagnostics"`
	From               *string                          `json:"from_t"`
	To                 *string                          `json:"to_t"`
	Coverage           []PairCoverage                   `json:"coverage"`
}

type PairCoverage struct {
	DatasetID            int64  `json:"dataset_id,omitempty"`
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
func (s *Store) RebuildMessagePairs(ctx context.Context, id int64, companions ...int64) (PairIndex, error) {
	out := PairIndex{Version: derived.Version, Diagnostics: map[string]int64{}, Coverage: []PairCoverage{}}
	if len(companions) > 1 {
		return out, errors.New("one explicit event companion is supported")
	}
	if len(companions) == 1 {
		out.EventDataset = companions[0]
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var kind string
		var meta []byte
		var companionMeta []byte
		var progress int64
		if e := tx.QueryRow(ctx, `SELECT kind,metadata,progress,status FROM datasets WHERE id=$1 FOR UPDATE`, id).Scan(&kind, &meta, &progress, &out.Status); e != nil {
			return e
		}
		if kind != "messages" && kind != "run" {
			return errors.New("dataset has no message evidence")
		}
		if out.EventDataset != 0 && kind != "messages" {
			return errors.New("event companion requires a journal/message dataset")
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
			c.DatasetID = id
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
					if x.Type == "frame" || x.Type == "gap" || out.EventDataset != 0 {
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
		if out.EventDataset != 0 {
			var sourceKind, sourceStatus string
			var sourceProgress, sourceNetwork, targetNetwork int64
			var sourceMeta []byte
			if e := tx.QueryRow(ctx, `SELECT kind,status,progress,network_id,metadata FROM datasets WHERE id=$1 FOR UPDATE`, out.EventDataset).Scan(&sourceKind, &sourceStatus, &sourceProgress, &sourceNetwork, &sourceMeta); e != nil {
				return e
			}
			if e := tx.QueryRow(ctx, `SELECT network_id FROM datasets WHERE id=$1`, id).Scan(&targetNetwork); e != nil {
				return e
			}
			companionMeta = sourceMeta
			if sourceKind != "run" || sourceStatus != "complete" || out.Status != "complete" || sourceNetwork != targetNetwork {
				return errors.New("association requires completed sources on one network")
			}
			if progress+sourceProgress > 1000000 {
				return ErrPairSource
			}
			events, e = readAssociationEvents(ctx, tx, out.EventDataset)
			if e != nil {
				return e
			}
			if int64(len(events)) != sourceProgress {
				return errors.New("event source count differs from progress")
			}
			proof := derived.VerifyAssociation(records, events)
			if proof.Status != "matched" {
				return errors.New("journal/event association is not fully matched")
			}
			for i := range proof.Anchors {
				for j := range proof.Anchors[i].Journal {
					proof.Anchors[i].Journal[j].DatasetID = id
				}
				for j := range proof.Anchors[i].Events {
					proof.Anchors[i].Events[j].DatasetID = out.EventDataset
				}
			}
			out.Association = &proof
			out.Records += sourceProgress
			associatedRecords, associatedEvents := derived.AssociatedSources(records, events, proof)
			var declarations struct {
				Legacy []logs.LegacyAssociation `json:"legacy_associations"`
			}
			if e = json.Unmarshal(sourceMeta, &declarations); e != nil {
				return e
			}

			inputRows, inputErr := tx.Query(ctx, `SELECT input_id,node,kind,profile,sha256 FROM log_inputs WHERE dataset_id=$1`, out.EventDataset)
			if inputErr != nil {
				return inputErr
			}
			inputMeta := map[string]logs.InputSummary{}
			for inputRows.Next() {
				var in logs.InputSummary
				if e = inputRows.Scan(&in.ID, &in.Node, &in.Kind, &in.Profile, &in.SHA256); e != nil {
					inputRows.Close()
					return e
				}
				inputMeta[in.ID] = in
			}
			e = inputRows.Err()
			inputRows.Close()
			if e != nil {
				return e
			}
			usedLegacy, legacyHashes := map[string]bool{}, map[string]bool{}
			for _, d := range declarations.Legacy {
				a, aok := inputMeta[d.Input]
				b, bok := inputMeta[d.NativeInput]
				if !aok || !bok || a.Kind != "log" || a.Profile != "gstable@740526d03" || b.Kind != "events" || a.SHA256 != d.SHA256 || b.SHA256 != d.NativeSHA256 || usedLegacy[d.Input] || legacyHashes[d.SHA256] {
					return errors.New("legacy association input snapshot mismatch")
				}
				usedLegacy[d.Input] = true
				legacyHashes[d.SHA256] = true
			}
			legacyEvents, legacyProofs, legacyErr := derived.DeclaredLegacyEvents(events, associatedEvents, declarations.Legacy)
			if legacyErr != nil {
				return legacyErr
			}
			out.LegacyAssociations = legacyProofs
			associatedEvents = append(associatedEvents, legacyEvents...)

			projection = derived.ProjectRecords(associatedRecords)
			projection.Counts["unassociated_message_records"] = int64(len(records) - len(associatedRecords))
			projection.Counts["unassociated_event_records"] = int64(len(events) - len(associatedEvents))
			excludedRecords, excludedEvents := derived.UnassociatedEvidence(records, events, associatedRecords, associatedEvents)
			projection.Issues = append(projection.Issues, excludedRecords...)
			projection.Counts["unassociated_message_observations"] = int64(len(excludedRecords))
			records = associatedRecords
			other, e := projectMessageEvents(associatedEvents)
			if e != nil {
				return e
			}
			other.Issues = append(other.Issues, excludedEvents...)
			other.Counts["unassociated_message_observations"] = int64(len(excludedEvents))
			coverage, e := readEventCoverage(ctx, tx, out.EventDataset, sourceStatus)
			if e != nil {
				return e
			}
			out.Coverage = append(out.Coverage, coverage...)
			for i := range projection.Endpoints {
				projection.Endpoints[i].Source.DatasetID = id
			}
			for i := range projection.Issues {
				projection.Issues[i].Source.DatasetID = id
			}
			for i := range other.Endpoints {
				for _, p := range legacyProofs {
					if other.Endpoints[i].Source.Input == p.Input {
						other.Endpoints[i].Source.Association = p.Status
					}
				}

				other.Endpoints[i].Source.DatasetID = out.EventDataset
			}
			for i := range other.Issues {
				other.Issues[i].Source.DatasetID = out.EventDataset
			}

			for i := range out.LegacyAssociations {
				for j := range out.LegacyAssociations[i].Anchors {
					out.LegacyAssociations[i].Anchors[j].Legacy.DatasetID = out.EventDataset
					out.LegacyAssociations[i].Anchors[j].Native.DatasetID = out.EventDataset
				}
			}
			xs := append(projection.Endpoints, other.Endpoints...)

			aliases := map[string]string{}
			for _, p := range legacyProofs {
				if old, ok := aliases[p.Address]; ok && old != p.Node {
					return errors.New("legacy address has ambiguous recording labels")
				}
				aliases[p.Address] = p.Node
			}
			for i := range xs {
				if n, ok := aliases[xs[i].Sender]; ok {
					xs[i].Sender = n
				}
				if n, ok := aliases[xs[i].Receiver]; ok {
					xs[i].Receiver = n
				}
			}
			xs = derived.EnrichEvents(xs, records)
			for i := range xs {
				if n, ok := aliases[xs[i].Author]; ok {
					xs[i].Author = n
				}
			}
			mixed := derived.MixProjection(xs)
			projection.Endpoints = mixed.Endpoints
			projection.Issues = append(projection.Issues, other.Issues...)
			projection.Issues = append(projection.Issues, mixed.Issues...)
			for k, v := range other.Counts {
				projection.Counts["events_"+k] = v
			}
			for k, v := range mixed.Counts {
				projection.Counts[k] += v
			}
			// Both captures must declare shared-host before cross-node values are
			// used. A missing or differently bounded companion clock stays unknown.
			var cm struct {
				Clock string `json:"clock"`
			}
			if e = json.Unmarshal(sourceMeta, &cm); e != nil {
				return e
			}
			if cm.Clock != "shared-host" || clock.Model != "shared-host" {
				clock.Model = "unknown"
			}
			if _, e = tx.Exec(ctx, `INSERT INTO message_pair_dependencies(dataset_id,source_id,progress,status,metadata) VALUES($1,$2,$3,$4,$5) ON CONFLICT(dataset_id) DO UPDATE SET source_id=EXCLUDED.source_id,progress=EXCLUDED.progress,status=EXCLUDED.status,metadata=EXCLUDED.metadata`, id, out.EventDataset, sourceProgress, sourceStatus, sourceMeta); e != nil {
				return e
			}
		} else {
			if _, e := tx.Exec(ctx, `DELETE FROM message_pair_dependencies WHERE dataset_id=$1`, id); e != nil {
				return e
			}
		}
		if kind == "run" {
			projection, e = projectMessageEvents(events)
			if e != nil {
				return e
			}
		}

		if len(projection.Endpoints) > 1000000 {
			return ErrPairSource
		}
		projection.Counts["records"] = out.Records
		out.Diagnostics = projection.Counts
		pairs := derived.PairEndpoints(projection.Endpoints, clock)
		out.Pairs = int64(len(pairs))
		out.Diagnostics["unpositioned_pairs"] = 0
		for _, p := range pairs {
			if p.ObservedFrom == nil || p.ObservedTo == nil {
				out.Diagnostics["unpositioned_pairs"]++
			}
		}
		out.Issues = int64(len(projection.Issues))
		sort.Slice(projection.Issues, func(i, j int) bool {
			a, _ := json.Marshal(projection.Issues[i])
			b, _ := json.Marshal(projection.Issues[j])
			return string(a) < string(b)
		})
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
				var observedFrom, observedTo any
				if p.ObservedFrom != nil {
					at, e := time.Parse(time.RFC3339Nano, *p.ObservedFrom)
					if e != nil {
						return e
					}
					observedFrom = axisNS(at)
				}
				if p.ObservedTo != nil {
					at, e := time.Parse(time.RFC3339Nano, *p.ObservedTo)
					if e != nil {
						return e
					}
					observedTo = axisNS(at)
				}
				batch.Queue(`INSERT INTO message_pairs(dataset_id,id,axis_ns,sender,receiver,phase,height,round,strength,path,clock,status,pair,observed_from_ns,observed_to_ns) VALUES($1,$2,$3::numeric,$4,$5,$6,nullif($7,'')::numeric,nullif($8,'')::numeric,$9,$10,$11,$12,$13,$14::numeric,$15::numeric)`, id, p.ID, axis, p.Sender, p.Receiver, p.Phase, p.Height, p.Round, p.Strength, p.Path, p.Clock, p.Status, b, observedFrom, observedTo)
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
		h := sha256.New()
		enc := json.NewEncoder(h)
		if e := enc.Encode(json.RawMessage(meta)); e != nil {
			return e
		}
		if e := enc.Encode(json.RawMessage(companionMeta)); e != nil {
			return e
		}
		if e := enc.Encode(out); e != nil {
			return e
		}
		for _, p := range pairs {
			if e := enc.Encode(p); e != nil {
				return e
			}
		}
		for _, x := range projection.Issues {
			if e := enc.Encode(x); e != nil {
				return e
			}
		}
		out.Snapshot = hex.EncodeToString(h.Sum(nil))
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
	Overlap                                                                             bool
	MaxPairs                                                                            int
	From, To                                                                            time.Time
	Sender, Receiver, Node, Phase, Height, Round, Strength, Path, Clock, Status, Metric string
}

// MessagePairData reads the index and rows in one repeatable-read snapshot.
// A committed ingest append invalidates the index rather than mixing versions.
func (s *Store) MessagePairData(ctx context.Context, id int64, f PairFilter) (PairIndex, []derived.Pair, error) {
	var index PairIndex
	pairs := []derived.Pair{}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var e error
		index, e = readPairIndex(ctx, tx, id)
		if e != nil {
			return e
		}
		var from, to any
		if !f.From.IsZero() {
			from = axisNS(f.From)
		}
		if !f.To.IsZero() {
			to = axisNS(f.To)
		}
		timePredicate := `($2::numeric IS NULL OR axis_ns>=$2) AND ($3::numeric IS NULL OR axis_ns<=$3)`
		if f.Overlap {
			timePredicate = `($2::numeric IS NULL OR observed_to_ns>=$2) AND ($3::numeric IS NULL OR observed_from_ns<=$3)`
		}
		maxPairs := 100000
		if f.MaxPairs > 0 && f.MaxPairs < maxPairs {
			maxPairs = f.MaxPairs
		}
		rows, e := tx.Query(ctx, `SELECT pair FROM message_pairs WHERE dataset_id=$1 AND `+timePredicate+` AND ($4='' OR sender=$4) AND ($5='' OR receiver=$5) AND ($6='' OR sender=$6 OR receiver=$6) AND ($7='' OR phase=$7) AND (($8='' AND $9='') OR EXISTS(SELECT 1 FROM jsonb_array_elements(pair->'views') v WHERE ($8='' OR v->>'height'=$8) AND ($9='' OR v->>'round'=$9))) AND ($10='' OR strength=$10) AND ($11='' OR path=$11) AND ($12='' OR clock=$12) AND ($13='' OR status=$13) AND ($14='' OR pair->>'metric'=$14) ORDER BY axis_ns NULLS LAST,id LIMIT $15`, id, from, to, f.Sender, f.Receiver, f.Node, f.Phase, f.Height, f.Round, f.Strength, f.Path, f.Clock, f.Status, f.Metric, maxPairs+1)
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
			if len(pairs) > maxPairs {
				return ErrPairWindow
			}
		}
		return rows.Err()
	})
	return index, pairs, err
}

func (s *Store) MessagePairIssues(ctx context.Context, id, after int64, limit int) ([]derived.Issue, error) {
	_, rows, _, e := s.MessageIssueData(ctx, id, IssueFilter{}, after, limit)
	out := []derived.Issue{}
	for _, r := range rows[:min(len(rows), limit)] {
		out = append(out, r.Issue)
	}
	return out, e
}

func readPairIndex(ctx context.Context, tx pgx.Tx, id int64) (PairIndex, error) {
	var index PairIndex
	var info []byte
	var ready bool
	e := tx.QueryRow(ctx, `SELECT i.info,coalesce(i.version=$2 AND i.progress=d.progress AND i.status=d.status AND i.metadata=d.metadata AND NOT EXISTS(SELECT 1 FROM message_pair_dependencies p LEFT JOIN datasets s ON s.id=p.source_id WHERE p.dataset_id=d.id AND (s.id IS NULL OR p.progress<>s.progress OR p.status<>s.status OR p.metadata<>s.metadata)),false) FROM datasets d LEFT JOIN message_pair_indexes i ON i.dataset_id=d.id WHERE d.id=$1`, id, derived.Version).Scan(&info, &ready)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return index, ErrNotFound
		}
		return index, e
	}
	if !ready {
		return index, ErrPairIndex
	}
	if e = json.Unmarshal(info, &index); e != nil {
		return index, e
	}

	for _, p := range index.LegacyAssociations {
		var a, b string
		err := tx.QueryRow(ctx, `SELECT (SELECT sha256 FROM log_inputs WHERE dataset_id=$1 AND input_id=$2),(SELECT sha256 FROM log_inputs WHERE dataset_id=$1 AND input_id=$3)`, index.EventDataset, p.Input, p.NativeInput).Scan(&a, &b)
		if err != nil || a != p.SHA256 || b != p.NativeSHA256 {
			return index, ErrPairIndex
		}
	}
	return index, nil
}

// Bound broadcast expansion before allocating either standalone or companion
// endpoint projections. Counting the maximum fanout also covers partial input.
func projectMessageEvents(events []logs.Event) (derived.Projection, error) {
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
		return derived.Projection{}, ErrPairSource
	}
	return derived.ProjectEvents(events), nil
}
