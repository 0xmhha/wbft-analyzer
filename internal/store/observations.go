package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft/observe/participation"
	"github.com/jackc/pgx/v5"
)

// ObservationNode uses decimal strings for heights and chain identity, avoiding
// JSON numeric precision loss in browser clients. These are recorded claims.
type ObservationNode struct {
	Impl            string                   `json:"impl"`
	Address         string                   `json:"address"`
	Validator       bool                     `json:"validator"`
	ChainID         string                   `json:"chain_id"`
	GenesisHash     string                   `json:"genesis_hash"`
	HeadNumber      string                   `json:"head_number"`
	HeadHash        string                   `json:"head_hash"`
	Mode            string                   `json:"mode"`
	Version         string                   `json:"version"`
	Build           string                   `json:"build"`
	LogProfile      string                   `json:"log_profile"`
	SignFloor       string                   `json:"sign_floor"`
	BLSPublicKey    string                   `json:"bls_public_key"`
	Improvements    []ObservationImprovement `json:"improvements"`
	RuleActivations map[string]string        `json:"rule_activations"`
	RulesDigest     string                   `json:"rules_digest"`
}
type ObservationImprovement struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}
type ObservationCapture struct {
	DatasetID    int64                          `json:"dataset_id"`
	From         string                         `json:"from"`
	To           string                         `json:"to"`
	Snapshot     string                         `json:"snapshot"`
	SourceKind   string                         `json:"source_kind"`
	SourceSHA256 string                         `json:"source_sha256"`
	Node         ObservationNode                `json:"node"`
	Comparison   observe.Comparison             `json:"comparison"`
	RoundChanges *observe.RoundChangeComparison `json:"round_changes,omitempty"`
	Calls        []ObservationCall              `json:"calls"`
}
type ObservationCall struct {
	Ordinal   int64    `json:"ordinal"`
	Method    string   `json:"method"`
	Params    []string `json:"params"`
	Status    string   `json:"status"`
	ErrorCode *int     `json:"error_code,omitempty"`
	SHA256    string   `json:"sha256"`
}
type ObservationRow struct {
	Height        string          `json:"height"`
	Gap           bool            `json:"gap"`
	Source        string          `json:"source"`
	Hash          string          `json:"hash"`
	Round         string          `json:"round"`
	Proposer      string          `json:"proposer"`
	Rounds        int64           `json:"rounds"`
	Validators    int64           `json:"validators"`
	LocalArrivals int64           `json:"local_arrivals"`
	CallOrdinal   int64           `json:"call_ordinal"`
	SourceOrdinal int64           `json:"source_ordinal"`
	Data          json.RawMessage `json:"data"`
}

func (s *Store) BeginObservations(ctx context.Context, k NetworkKey, name string, metadata json.RawMessage) (Dataset, func(), error) {
	return s.beginDataset(ctx, k, name, "observations", metadata)
}

// PutObservation stores a normalized capture atomically. Reusing a source name
// with different content is refused; historical observations are never merged
// into event/journal completeness, and raw RPC envelopes are not persisted.
func (s *Store) PutObservation(ctx context.Context, id int64, sourceKind, sourceSHA string, snap observe.Snapshot) error {
	if !oneSourceKind(sourceKind) || len(sourceSHA) != 64 {
		return errors.New("invalid observation provenance")
	}
	if _, e := hex.DecodeString(sourceSHA); e != nil {
		return errors.New("invalid observation source hash")
	}
	n := snap.Node
	info := ObservationCapture{DatasetID: id, From: snap.From, To: snap.To, SourceKind: sourceKind, SourceSHA256: sourceSHA, Node: ObservationNode{Impl: n.Impl, Address: strings.ToLower(n.Address.String()), Validator: n.Validator, ChainID: n.ChainID.String(), GenesisHash: n.GenesisHash.String(), HeadNumber: n.Head.Number, HeadHash: n.Head.Hash.String(), Mode: n.Mode, Version: n.Version, Build: n.Build, LogProfile: n.LogProfile, SignFloor: n.SignFloor, BLSPublicKey: n.BLSPublicKey, Improvements: []ObservationImprovement{}, RuleActivations: map[string]string{}, RulesDigest: n.RulesDigest.String()}, Comparison: snap.Comparison, RoundChanges: snap.RoundChanges, Calls: []ObservationCall{}}
	for _, x := range n.Improvements {
		info.Node.Improvements = append(info.Node.Improvements, ObservationImprovement{x.Name, x.Source})
	}
	for k, v := range n.RuleActivations {
		info.Node.RuleActivations[string(k)] = v
	}
	for _, c := range snap.Calls {
		info.Calls = append(info.Calls, ObservationCall{c.Ordinal, c.Method, c.Params, c.Status, c.ErrorCode, c.SHA256})
	}
	raw, e := json.Marshal(snap)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(raw)
	info.Snapshot = hex.EncodeToString(sum[:])
	meta, e := json.Marshal(info)
	if e != nil {
		return e
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var nid int64
		var kind, chain, genesis string
		if e := tx.QueryRow(ctx, `SELECT d.network_id,d.kind,n.chain_id,n.genesis_hash FROM datasets d JOIN networks n ON n.id=d.network_id WHERE d.id=$1 FOR UPDATE OF d`, id).Scan(&nid, &kind, &chain, &genesis); e != nil {
			return e
		}
		if kind != "observations" || chain != info.Node.ChainID || genesis != info.Node.GenesisHash {
			return errors.New("observation dataset identity mismatch")
		}
		tag, e := tx.Exec(ctx, `INSERT INTO observation_captures(dataset_id,node,snapshot,info) VALUES($1,$2,$3,$4) ON CONFLICT(dataset_id) DO UPDATE SET snapshot=observation_captures.snapshot WHERE observation_captures.snapshot=EXCLUDED.snapshot AND observation_captures.info=EXCLUDED.info`, id, info.Node.Address, info.Snapshot, meta)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return errors.New("observation source content conflict")
		}
		batch := &pgx.Batch{}
		for _, c := range snap.Calls {
			data, e := json.Marshal(c)
			if e != nil {
				return e
			}
			batch.Queue(`INSERT INTO observation_calls(dataset_id,ordinal,method,call) VALUES($1,$2,$3,$4) ON CONFLICT(dataset_id,ordinal) DO UPDATE SET call=observation_calls.call WHERE observation_calls.call=EXCLUDED.call`, id, c.Ordinal, c.Method, data)
			if c.Method == "wbft_participation" && c.Status == "available" {
				var records []participation.Record
				if e = json.Unmarshal(c.Data, &records); e != nil {
					return e
				}
				for i, r := range records {
					row := ObservationRow{Height: r.Height, Gap: r.Gap, Source: r.Source, Hash: r.Hash, Round: r.Round, Proposer: r.Proposer, Rounds: int64(len(r.Rounds)), Validators: int64(len(r.Validators)), CallOrdinal: c.Ordinal, SourceOrdinal: int64(i + 1)}
					for _, v := range r.Validators {
						for _, seen := range []*participation.Seen{v.Preprepare, v.Prepare, v.Commit, v.RoundChange} {
							if seen != nil {
								row.LocalArrivals++
							}
						}
					}
					row.Data, e = json.Marshal(r)
					if e != nil {
						return e
					}
					b, e := json.Marshal(row)
					if e != nil {
						return e
					}
					batch.Queue(`INSERT INTO observation_participation(dataset_id,height,ordinal,row_) VALUES($1,$2::numeric,$3,$4) ON CONFLICT(dataset_id,height) DO UPDATE SET row_=observation_participation.row_ WHERE observation_participation.row_=EXCLUDED.row_`, id, r.Height, i+1, b)
				}
			}
		}
		return tx.SendBatch(ctx, batch).Close()
	})
}
func oneSourceKind(k string) bool { return k == "archive" || k == "rpc" }
func (s *Store) ObservationCapture(ctx context.Context, id int64) (ObservationCapture, error) {
	var out ObservationCapture
	var raw []byte
	e := s.pool.QueryRow(ctx, `SELECT info FROM observation_captures WHERE dataset_id=$1`, id).Scan(&raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if e != nil {
		return out, e
	}
	e = json.Unmarshal(raw, &out)
	return out, e
}
func (s *Store) ObservationCall(ctx context.Context, id, ordinal int64) (observe.Call, error) {
	var out observe.Call
	var raw []byte
	e := s.pool.QueryRow(ctx, `SELECT call FROM observation_calls WHERE dataset_id=$1 AND ordinal=$2`, id, ordinal).Scan(&raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if e != nil {
		return out, e
	}
	e = json.Unmarshal(raw, &out)
	return out, e
}
func (s *Store) ObservationRows(ctx context.Context, id int64, from, to string, offset int64, limit int) ([]ObservationRow, int64, error) {
	rows := []ObservationRow{}
	var total int64
	a, b, e := observe.Range(from, to)
	if e != nil || offset < 0 || limit < 1 || limit > 1000 {
		return nil, 0, errors.New("invalid observation query")
	}
	info, e := s.ObservationCapture(ctx, id)
	if e != nil {
		return nil, 0, e
	}
	lo, hi, _ := observe.Range(info.From, info.To)
	if a.Cmp(lo) < 0 || b.Cmp(hi) > 0 {
		return nil, 0, fmt.Errorf("query exceeds observation capture scope")
	}
	if e = s.pool.QueryRow(ctx, `SELECT count(*) FROM observation_participation WHERE dataset_id=$1 AND height BETWEEN $2::numeric AND $3::numeric`, id, from, to).Scan(&total); e != nil {
		return nil, 0, e
	}
	rs, e := s.pool.Query(ctx, `SELECT row_ FROM observation_participation WHERE dataset_id=$1 AND height BETWEEN $2::numeric AND $3::numeric ORDER BY height OFFSET $4 LIMIT $5`, id, from, to, offset, limit+1)
	if e != nil {
		return nil, 0, e
	}
	defer rs.Close()
	for rs.Next() {
		var raw []byte
		var row ObservationRow
		if e = rs.Scan(&raw); e != nil {
			return nil, 0, e
		}
		if e = json.Unmarshal(raw, &row); e != nil {
			return nil, 0, e
		}
		rows = append(rows, row)
	}
	return rows, total, rs.Err()
}
