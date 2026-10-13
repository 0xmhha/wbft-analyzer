package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/derive/missing"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/jackc/pgx/v5"
)

var ErrMissingIndex = errors.New("missing classification index is absent or stale; run reindex missing")
var ErrMissingScope = errors.New("missing classification requires stored canonical headers and a bounded source/range")

type MissingIndex struct {
	Version        string           `json:"version"`
	Snapshot       string           `json:"snapshot"`
	From           string           `json:"from"`
	To             string           `json:"to"`
	DatasetID      int64            `json:"dataset_id"`
	Messages       int64            `json:"messages,omitempty"`
	EventRecords   int64            `json:"event_records"`
	MessageRecords int64            `json:"message_records"`
	Cells          int64            `json:"cells"`
	Counts         map[string]int64 `json:"counts"`
}
type MissingFilter struct {
	From, To                        uint64
	Validator, Phase, Class, Reason string
}

type missingDataset struct {
	Kind, Status      string
	Progress, Network int64
	Metadata          json.RawMessage
}

func missingSource(ctx context.Context, tx pgx.Tx, id int64, lock bool) (missingDataset, error) {
	var d missingDataset
	q := `SELECT kind,status,progress,network_id,metadata FROM datasets WHERE id=$1`
	if lock {
		q += ` FOR UPDATE`
	}
	e := tx.QueryRow(ctx, q, id).Scan(&d.Kind, &d.Status, &d.Progress, &d.Network, &d.Metadata)
	return d, e
}
func missingInputHash(ctx context.Context, tx pgx.Tx, id int64) (string, error) {
	var raw []byte
	e := tx.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.input_id),'[]'::jsonb) FROM (SELECT i.input_id,i.node,i.kind,i.profile,i.profile_sha256,i.sha256,i.bytes,i.stats,coalesce(r.records,0) AS records,coalesce(r.last_line,0) AS last_line FROM log_inputs i LEFT JOIN (SELECT input_id,count(*) AS records,max(line) AS last_line FROM log_events WHERE dataset_id=$1 GROUP BY input_id) r ON r.input_id=i.input_id WHERE i.dataset_id=$1) x`, id).Scan(&raw)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func missingHash(x any) string {
	b, _ := json.Marshal(x)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func missingEvents(ctx context.Context, tx pgx.Tx, id int64, status string) ([]logs.Event, []missing.Input, error) {
	inputs := []missing.Input{}
	rows, e := tx.Query(ctx, `SELECT input_id,kind,stats FROM log_inputs WHERE dataset_id=$1 ORDER BY input_id`, id)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var in missing.Input
		var kind string
		var raw []byte
		if e = rows.Scan(&in.ID, &kind, &raw); e != nil {
			rows.Close()
			return nil, nil, e
		}
		if e = json.Unmarshal(raw, &in.Stats); e != nil {
			rows.Close()
			return nil, nil, e
		}
		in.Complete = status == "complete" && kind == "events"
		inputs = append(inputs, in)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	rows, e = tx.Query(ctx, `SELECT event FROM log_events WHERE dataset_id=$1 ORDER BY input_id,line LIMIT 1000001`, id)
	if e != nil {
		return nil, nil, e
	}
	defer rows.Close()
	events := []logs.Event{}
	for rows.Next() {
		var raw []byte
		var x LogEvent
		if e = rows.Scan(&raw); e != nil {
			return nil, nil, e
		}
		if e = json.Unmarshal(raw, &x); e != nil {
			return nil, nil, e
		}
		r, e := normalized(x)
		if e != nil {
			return nil, nil, e
		}
		events = append(events, r)
		if len(events) > 1000000 {
			return nil, nil, ErrMissingScope
		}
	}
	return events, inputs, rows.Err()
}
func missingRecords(ctx context.Context, tx pgx.Tx, id int64) ([]source.Record, error) {
	if id == 0 {
		return nil, nil
	}
	rows, e := tx.Query(ctx, `SELECT record FROM message_records WHERE dataset_id=$1 ORDER BY input_id,file,ordinal LIMIT 1000001`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	records := []source.Record{}
	for rows.Next() {
		var raw []byte
		var x source.Record
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(raw, &x); e != nil {
			return nil, e
		}
		records = append(records, x)
		if len(records) > 1000000 {
			return nil, ErrMissingScope
		}
	}
	return records, rows.Err()
}

// Header numbers include source-wide imported heads used for sender coverage.
// A copy in the classification range must match its canonical hash. The digest
// is recomputed at read time, so new/deleted copies or a new carrier stale it.
func missingHeaders(ctx context.Context, tx pgx.Tx, network int64, from, to uint64, numbers []string) ([]headers.Fact, []missing.Copy, string, error) {
	if to == ^uint64(0) {
		return nil, nil, "", ErrMissingScope
	}
	rows, e := tx.Query(ctx, `SELECT fact FROM heights WHERE network_id=$1 AND (index_ BETWEEN $2::numeric AND $3::numeric OR fact->>'number'=ANY($4::text[])) ORDER BY index_ LIMIT 100002`, network, strconv.FormatUint(from, 10), strconv.FormatUint(to+1, 10), numbers)
	if e != nil {
		return nil, nil, "", e
	}
	facts := []headers.Fact{}
	for rows.Next() {
		var raw []byte
		var x headers.Fact
		if e = rows.Scan(&raw); e != nil {
			rows.Close()
			return nil, nil, "", e
		}
		if e = json.Unmarshal(raw, &x); e != nil {
			rows.Close()
			return nil, nil, "", e
		}
		facts = append(facts, x)
		if len(facts) > 100001 {
			rows.Close()
			return nil, nil, "", ErrMissingScope
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, "", e
	}
	rows, e = tx.Query(ctx, `SELECT hc.dataset_id,hc.copy FROM header_copies hc JOIN datasets d ON d.id=hc.dataset_id WHERE d.network_id=$1 AND hc.index_ BETWEEN $2::numeric AND $3::numeric ORDER BY hc.dataset_id,hc.index_,hc.node LIMIT 100001`, network, strconv.FormatUint(from, 10), strconv.FormatUint(to, 10))
	if e != nil {
		return nil, nil, "", e
	}
	copies := []missing.Copy{}
	for rows.Next() {
		var raw []byte
		var x missing.Copy
		if e = rows.Scan(&x.DatasetID, &raw); e != nil {
			rows.Close()
			return nil, nil, "", e
		}
		if e = json.Unmarshal(raw, &x.Copy); e != nil {
			rows.Close()
			return nil, nil, "", e
		}
		copies = append(copies, x)
		if len(copies) > 100000 {
			rows.Close()
			return nil, nil, "", ErrMissingScope
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, "", e
	}
	hash := missingHash(struct {
		Facts  []headers.Fact
		Copies []missing.Copy
	}{facts, copies})
	return facts, copies, hash, nil
}

// RebuildMissing reads one execution and its verified optional journal within
// one atomic transaction. Source-wide identity precedes displayed-range filters.
// GET never runs classification and never replaces an existing projection.
func (s *Store) RebuildMissing(ctx context.Context, id, messageID int64, from, to uint64) (MissingIndex, error) {
	out := MissingIndex{Version: missing.Version, From: strconv.FormatUint(from, 10), To: strconv.FormatUint(to, 10), DatasetID: id, Messages: messageID, Counts: map[string]int64{}}
	if id <= 0 || messageID < 0 || to < from || to == ^uint64(0) || to-from >= 1024 {
		return out, ErrMissingScope
	}
	e := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if messageID > 0 {
			if _, e := missingSource(ctx, tx, messageID, true); e != nil {
				return e
			}
		}
		d, e := missingSource(ctx, tx, id, true)
		if e != nil {
			return e
		}
		if d.Kind != "run" {
			return ErrMissingScope
		}
		events, inputs, e := missingEvents(ctx, tx, id, d.Status)
		if e != nil {
			return e
		}
		if d.Progress != int64(len(events)) {
			return errors.New("event progress does not match stored records")
		}
		var pairSnapshot string
		if messageID > 0 {
			m, e := missingSource(ctx, tx, messageID, true)
			if e != nil {
				return e
			}
			if m.Kind != "messages" || m.Network != d.Network {
				return ErrMissingScope
			}
			index, e := readPairIndex(ctx, tx, messageID)
			if e != nil {
				return e
			}
			if index.EventDataset != id || index.Association == nil || index.Association.Status != "matched" {
				return errors.New("missing requires a verified journal/event execution companion")
			}
			pairSnapshot = index.Snapshot
		}
		inputHash, e := missingInputHash(ctx, tx, id)
		if e != nil {
			return e
		}
		records, e := missingRecords(ctx, tx, messageID)
		if e != nil {
			return e
		}
		numbers := []string{}
		seen := map[string]bool{}
		for _, x := range events {
			if x.Record.Kind == "NEW_HEAD" && x.Record.View != nil && !seen[x.Record.View.Seq] {
				seen[x.Record.View.Seq] = true
				numbers = append(numbers, x.Record.View.Seq)
			}
		}
		sort.Strings(numbers)
		facts, copies, headerHash, e := missingHeaders(ctx, tx, d.Network, from, to, numbers)
		if e != nil {
			return e
		}
		indexes := map[string]bool{}
		for _, f := range facts {
			indexes[f.Index] = true
		}
		for n := from; n <= to; n++ {
			if !indexes[strconv.FormatUint(n, 10)] {
				return fmt.Errorf("missing canonical header at index %d", n)
			}
		}
		heights, e := missing.HeaderProjection(facts, copies)
		if e != nil {
			return e
		}
		cells, e := missing.BuildRange(heights, events, records, inputs, from, to)
		if e != nil {
			return e
		}
		selected := []missing.Cell{}
		for _, c := range cells {
			n, e := strconv.ParseUint(c.Index, 10, 64)
			if e != nil {
				return e
			}
			if n < from || n > to {
				continue
			}
			for i := range c.Evidence {
				c.Evidence[i].Source.DatasetID = id
			}
			selected = append(selected, c)
			out.Counts[c.Class]++
			if len(selected) > 100000 {
				return ErrMissingScope
			}
		}
		sort.Slice(selected, func(i, j int) bool {
			a, b := selected[i], selected[j]
			ai, _ := strconv.ParseUint(a.Index, 10, 64)
			bi, _ := strconv.ParseUint(b.Index, 10, 64)
			if ai != bi {
				return ai < bi
			}
			if a.Validator != b.Validator {
				return a.Validator < b.Validator
			}
			return a.Phase < b.Phase
		})
		out.EventRecords, out.MessageRecords, out.Cells = int64(len(events)), int64(len(records)), int64(len(selected))
		out.Snapshot = missingHash(struct {
			Info    MissingIndex
			Parent  missingDataset
			Pair    string
			Headers string
			Input   string
			Cells   []missing.Cell
		}{out, d, pairSnapshot, headerHash, inputHash, selected})
		info, e := json.Marshal(out)
		if e != nil {
			return e
		}
		nums, e := json.Marshal(numbers)
		if e != nil {
			return e
		}
		var message any
		if messageID > 0 {
			message = messageID
		}
		_, e = tx.Exec(ctx, `INSERT INTO missing_indexes(dataset_id,version,from_index,to_index,status,progress,metadata,message_id,had_messages,message_snapshot,header_numbers,header_snapshot,info,input_snapshot) VALUES($1,$2,$3::numeric,$4::numeric,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(dataset_id) DO UPDATE SET version=EXCLUDED.version,from_index=EXCLUDED.from_index,to_index=EXCLUDED.to_index,status=EXCLUDED.status,progress=EXCLUDED.progress,metadata=EXCLUDED.metadata,message_id=EXCLUDED.message_id,had_messages=EXCLUDED.had_messages,message_snapshot=EXCLUDED.message_snapshot,header_numbers=EXCLUDED.header_numbers,header_snapshot=EXCLUDED.header_snapshot,info=EXCLUDED.info,input_snapshot=EXCLUDED.input_snapshot`, id, missing.Version, out.From, out.To, d.Status, d.Progress, d.Metadata, message, messageID > 0, pairSnapshot, nums, headerHash, info, inputHash)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM missing_cells WHERE dataset_id=$1`, id); e != nil {
			return e
		}
		batch := &pgx.Batch{}
		for i, c := range selected {
			raw, e := json.Marshal(c)
			if e != nil {
				return e
			}
			batch.Queue(`INSERT INTO missing_cells(dataset_id,ordinal,index_,validator,phase,class,reason,cell) VALUES($1,$2,$3::numeric,$4,$5,$6,$7,$8)`, id, i+1, c.Index, c.Validator, c.Phase, c.Class, c.Reason, raw)
		}
		return tx.SendBatch(ctx, batch).Close()
	})
	return out, e
}

func readMissingIndex(ctx context.Context, tx pgx.Tx, id int64) (MissingIndex, error) {
	var out MissingIndex
	var info, nums []byte
	var ready, had bool
	var message *int64
	var pairHash, headerHash, inputHash string
	e := tx.QueryRow(ctx, `SELECT i.info,i.header_numbers,coalesce(i.header_snapshot,''),coalesce(i.had_messages,false),i.message_id,coalesce(i.message_snapshot,''),coalesce(i.input_snapshot,''),coalesce(i.version=$2 AND i.status=d.status AND i.progress=d.progress AND i.metadata=d.metadata,false) FROM datasets d LEFT JOIN missing_indexes i ON i.dataset_id=d.id WHERE d.id=$1`, id, missing.Version).Scan(&info, &nums, &headerHash, &had, &message, &pairHash, &inputHash, &ready)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return out, ErrNotFound
		}
		return out, e
	}
	if !ready {
		return out, ErrMissingIndex
	}
	if e = json.Unmarshal(info, &out); e != nil {
		return out, e
	}
	currentInput, e := missingInputHash(ctx, tx, id)
	if e != nil {
		return out, e
	}
	if inputHash != currentInput {
		return out, ErrMissingIndex
	}
	if had {
		if message == nil {
			return out, ErrMissingIndex
		}
		p, e := readPairIndex(ctx, tx, *message)
		if e != nil || p.Snapshot != pairHash {
			return out, ErrMissingIndex
		}
	}
	d, e := missingSource(ctx, tx, id, false)
	if e != nil {
		return out, e
	}
	var numbers []string
	if e = json.Unmarshal(nums, &numbers); e != nil {
		return out, e
	}
	from, e := strconv.ParseUint(out.From, 10, 64)
	if e != nil {
		return out, e
	}
	to, e := strconv.ParseUint(out.To, 10, 64)
	if e != nil {
		return out, e
	}
	_, _, hash, e := missingHeaders(ctx, tx, d.Network, from, to, numbers)
	if e != nil {
		return out, e
	}
	if hash != headerHash {
		return out, ErrMissingIndex
	}
	return out, nil
}
func (s *Store) MissingData(ctx context.Context, id int64, f MissingFilter, offset int64, limit int) (MissingIndex, []missing.Cell, int64, error) {
	var index MissingIndex
	cells := []missing.Cell{}
	var total int64
	if f.To < f.From || f.To-f.From >= 1024 || offset < 0 || limit < 1 || limit > 1000 {
		return index, nil, 0, ErrMissingScope
	}
	e := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var e error
		index, e = readMissingIndex(ctx, tx, id)
		if e != nil {
			return e
		}
		from, _ := strconv.ParseUint(index.From, 10, 64)
		to, _ := strconv.ParseUint(index.To, 10, 64)
		if f.From < from || f.To > to {
			return ErrMissingScope
		}
		args := []any{id, strconv.FormatUint(f.From, 10), strconv.FormatUint(f.To, 10), f.Validator, f.Phase, f.Class, f.Reason}
		where := `dataset_id=$1 AND index_ BETWEEN $2::numeric AND $3::numeric AND ($4='' OR validator=$4) AND ($5='' OR phase=$5) AND ($6='' OR class=$6) AND ($7='' OR reason=$7)`
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM missing_cells WHERE `+where, args...).Scan(&total); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT cell FROM missing_cells WHERE `+where+` ORDER BY ordinal OFFSET $8 LIMIT $9`, append(args, offset, limit+1)...)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var c missing.Cell
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			if e = json.Unmarshal(raw, &c); e != nil {
				return e
			}
			cells = append(cells, c)
		}
		return rows.Err()
	})
	return index, cells, total, e
}

func (s *Store) MissingIndex(ctx context.Context, id int64) (MissingIndex, error) {
	var out MissingIndex
	e := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error { var e error; out, e = readMissingIndex(ctx, tx, id); return e })
	return out, e
}
