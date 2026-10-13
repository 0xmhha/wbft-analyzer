package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/derive/observation"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/jackc/pgx/v5"
)

var ErrObservationHeaderIndex = errors.New("observation/header binding is absent or stale; run reindex observations")

type ObservationHeaderIndex struct {
	DatasetID   int64               `json:"dataset_id"`
	Version     string              `json:"version"`
	Snapshot    string              `json:"snapshot"`
	From        string              `json:"from"`
	To          string              `json:"to"`
	Rows        int64               `json:"rows"`
	BoundCopies int64               `json:"bound_copies"`
	Counts      map[string]int64    `json:"counts"`
	Summary     observation.Summary `json:"summary"`
	ProofLevel  string              `json:"proof_level"`
}
type ObservationHeaderFilter struct{ From, To, Kind, Status string }

func observationHeaderSource(ctx context.Context, tx pgx.Tx, id int64, lock bool) (ObservationCapture, missingDataset, []observe.Call, string, error) {
	var info ObservationCapture
	d, e := missingSource(ctx, tx, id, lock)
	if e != nil {
		return info, d, nil, "", e
	}
	if d.Kind != "observations" || d.Status != "complete" {
		return info, d, nil, "", ErrObservationHeaderIndex
	}
	var raw []byte
	if e = tx.QueryRow(ctx, `SELECT info FROM observation_captures WHERE dataset_id=$1`, id).Scan(&raw); e != nil {
		return info, d, nil, "", e
	}
	if e = json.Unmarshal(raw, &info); e != nil {
		return info, d, nil, "", e
	}
	rows, e := tx.Query(ctx, `SELECT call FROM observation_calls WHERE dataset_id=$1 ORDER BY ordinal LIMIT 4097`, id)
	if e != nil {
		return info, d, nil, "", e
	}
	defer rows.Close()
	calls := []observe.Call{}
	for rows.Next() {
		var raw []byte
		var c observe.Call
		if e = rows.Scan(&raw); e != nil {
			return info, d, nil, "", e
		}
		if e = json.Unmarshal(raw, &c); e != nil {
			return info, d, nil, "", e
		}
		calls = append(calls, c)
	}
	if e = rows.Err(); e != nil {
		return info, d, nil, "", e
	}
	if len(calls) > observe.MaxCalls || int64(len(calls)) != d.Progress || len(calls) != len(info.Calls) {
		return info, d, nil, "", fmt.Errorf("%w: source count mismatch", ErrObservationHeaderIndex)
	}
	hash := missingHash(struct {
		Capture ObservationCapture
		Dataset missingDataset
		Calls   []observe.Call
	}{info, d, calls})
	return info, d, calls, hash, nil
}
func observationHeaderNumbers(info ObservationCapture) ([]string, error) {
	from, to, e := observe.Range(info.From, info.To)
	if e != nil {
		return nil, e
	}
	numbers := []string{}
	for h := from; h.Cmp(to) <= 0; h.Add(h, big.NewInt(1)) {
		numbers = append(numbers, h.String())
	}
	seen := false
	for _, n := range numbers {
		seen = seen || n == info.Node.HeadNumber
	}
	if !seen {
		numbers = append(numbers, info.Node.HeadNumber)
	}
	sort.Strings(numbers)
	return numbers, nil
}
func canonicalObservationHeaders(ctx context.Context, tx pgx.Tx, net int64, numbers []string) ([]headers.Fact, string, error) {
	rows, e := tx.Query(ctx, `SELECT DISTINCT x.fact FROM heights h LEFT JOIN heights p ON p.network_id=h.network_id AND p.index_=h.index_-1 LEFT JOIN heights c ON c.network_id=h.network_id AND c.index_=h.index_+1 CROSS JOIN LATERAL (VALUES(h.fact),(p.fact),(c.fact)) x(fact) WHERE h.network_id=$1 AND h.fact->>'number'=ANY($2::text[]) AND x.fact IS NOT NULL LIMIT 6145`, net, numbers)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	facts := []headers.Fact{}
	for rows.Next() {
		var raw []byte
		var f headers.Fact
		if e = rows.Scan(&raw); e != nil {
			return nil, "", e
		}
		if e = json.Unmarshal(raw, &f); e != nil {
			return nil, "", e
		}
		facts = append(facts, f)
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	if len(facts) > 6144 {
		return nil, "", fmt.Errorf("canonical dependency scope exceeds limit")
	}
	sort.Slice(facts, func(i, j int) bool {
		a, _ := strconv.ParseUint(facts[i].Index, 10, 64)
		b, _ := strconv.ParseUint(facts[j].Index, 10, 64)
		return a < b
	})
	return facts, missingHash(facts), nil
}
func (s *Store) RebuildObservationHeaders(ctx context.Context, id int64) (ObservationHeaderIndex, error) {
	out := ObservationHeaderIndex{DatasetID: id, Version: observation.Version, Counts: map[string]int64{}, ProofLevel: "structural_metadata_only"}
	e := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		info, d, calls, source, e := observationHeaderSource(ctx, tx, id, true)
		if e != nil {
			return e
		}
		numbers, e := observationHeaderNumbers(info)
		if e != nil {
			return e
		}
		facts, headerHash, e := canonicalObservationHeaders(ctx, tx, d.Network, numbers)
		if e != nil {
			return e
		}
		result, e := observation.Build(facts, calls, info.Node.Address)
		if e != nil {
			return e
		}
		out.From, out.To, out.Rows, out.Summary = info.From, info.To, int64(len(result.Rows)), result.Summary
		for _, r := range result.Rows {
			out.Counts[r.Kind+":"+r.Status]++
			if r.Copy != nil {
				out.BoundCopies++
			}
		}
		out.Snapshot = missingHash(struct {
			Version, Source, Headers string
			Result                   observation.Result
		}{observation.Version, source, headerHash, result})
		raw, e := json.Marshal(out)
		if e != nil {
			return e
		}
		nums, _ := json.Marshal(numbers)
		if _, e = tx.Exec(ctx, `INSERT INTO observation_header_indexes(dataset_id,version,source_snapshot,header_numbers,header_snapshot,info) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(dataset_id) DO UPDATE SET version=EXCLUDED.version,source_snapshot=EXCLUDED.source_snapshot,header_numbers=EXCLUDED.header_numbers,header_snapshot=EXCLUDED.header_snapshot,info=EXCLUDED.info`, id, observation.Version, source, nums, headerHash, raw); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM observation_header_rows WHERE dataset_id=$1`, id); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM header_copies WHERE dataset_id=$1 AND copy->>'source'='rpc_observation_structural'`, id); e != nil {
			return e
		}
		batch := &pgx.Batch{}
		for i, r := range result.Rows {
			raw, e := json.Marshal(r)
			if e != nil {
				return e
			}
			var height any
			if r.Height != "" {
				height = r.Height
			}
			batch.Queue(`INSERT INTO observation_header_rows(dataset_id,ordinal,height,kind,status,row_) VALUES($1,$2,$3::numeric,$4,$5,$6)`, id, i+1, height, r.Kind, r.Status, raw)
		}
		if e = tx.SendBatch(ctx, batch).Close(); e != nil {
			return e
		}
		for _, r := range result.Rows {
			if r.Copy == nil {
				continue
			}
			c := r.Copy
			raw, e := json.Marshal(c)
			if e != nil {
				return e
			}
			tag, e := tx.Exec(ctx, `INSERT INTO header_copies(dataset_id,node,index_,hash,copy) VALUES($1,$2,$3::numeric,$4,$5) ON CONFLICT(dataset_id,node,hash) DO UPDATE SET copy=EXCLUDED.copy WHERE header_copies.copy->>'source'='rpc_observation_structural'`, id, c.Node, c.Index, c.Hash, raw)
			if e != nil {
				return e
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("conflicting node copy provenance")
			}
		}
		return nil
	})
	return out, e
}
func readObservationHeaderIndex(ctx context.Context, tx pgx.Tx, id int64) (ObservationHeaderIndex, error) {
	var out ObservationHeaderIndex
	var version, source, headerHash string
	var raw, nums []byte
	e := tx.QueryRow(ctx, `SELECT version,source_snapshot,header_numbers,header_snapshot,info FROM observation_header_indexes WHERE dataset_id=$1`, id).Scan(&version, &source, &nums, &headerHash, &raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, ErrObservationHeaderIndex
	}
	if e != nil {
		return out, e
	}
	if version != observation.Version {
		return out, ErrObservationHeaderIndex
	}
	_, d, _, current, e := observationHeaderSource(ctx, tx, id, false)
	if e != nil {
		return out, e
	}
	if source != current {
		return out, ErrObservationHeaderIndex
	}
	var numbers []string
	if e = json.Unmarshal(nums, &numbers); e != nil {
		return out, e
	}
	_, hash, e := canonicalObservationHeaders(ctx, tx, d.Network, numbers)
	if e != nil {
		return out, e
	}
	if hash != headerHash {
		return out, ErrObservationHeaderIndex
	}
	e = json.Unmarshal(raw, &out)
	return out, e
}
func (s *Store) ObservationHeaderIndex(ctx context.Context, id int64) (ObservationHeaderIndex, error) {
	var out ObservationHeaderIndex
	e := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error { var e error; out, e = readObservationHeaderIndex(ctx, tx, id); return e })
	return out, e
}
func (s *Store) ObservationHeaderRows(ctx context.Context, id int64, f ObservationHeaderFilter, offset int64, limit int) (ObservationHeaderIndex, []observation.Binding, int64, error) {
	var info ObservationHeaderIndex
	out := []observation.Binding{}
	var total int64
	a, b, e := observe.Range(f.From, f.To)
	if e != nil || offset < 0 || limit < 1 || limit > 1000 {
		return info, out, 0, fmt.Errorf("invalid binding query")
	}
	e = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var e error
		info, e = readObservationHeaderIndex(ctx, tx, id)
		if e != nil {
			return e
		}
		lo, hi, _ := observe.Range(info.From, info.To)
		if a.Cmp(lo) < 0 || b.Cmp(hi) > 0 {
			return fmt.Errorf("query exceeds binding scope")
		}
		where := `dataset_id=$1 AND (kind='head' OR height IS NULL OR height BETWEEN $2::numeric AND $3::numeric) AND ($4='' OR kind=$4) AND ($5='' OR status=$5)`
		args := []any{id, f.From, f.To, f.Kind, f.Status}
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM observation_header_rows WHERE `+where, args...).Scan(&total); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT row_ FROM observation_header_rows WHERE `+where+` ORDER BY ordinal OFFSET $6 LIMIT $7`, append(args, offset, limit+1)...)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var r observation.Binding
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			if e = json.Unmarshal(raw, &r); e != nil {
				return e
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return info, out, total, e
}

func checkObservationCopies(ctx context.Context, tx pgx.Tx, network int64) error {
	rows, e := tx.Query(ctx, `SELECT DISTINCT d.id FROM header_copies hc JOIN datasets d ON d.id=hc.dataset_id WHERE d.network_id=$1 AND d.kind='observations' AND hc.copy->>'source'='rpc_observation_structural' ORDER BY d.id`, network)
	if e != nil {
		return e
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		if _, e = readObservationHeaderIndex(ctx, tx, id); e != nil {
			return e
		}
	}
	return nil
}
