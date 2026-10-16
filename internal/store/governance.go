package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/jackc/pgx/v5"
)

type GovernanceCall struct {
	Ordinal   int                `json:"ordinal"`
	Request   governance.Request `json:"request"`
	Status    string             `json:"status"`
	ErrorCode *int               `json:"error_code,omitempty"`
	SHA256    string             `json:"sha256"`
}

type GovernanceCapture struct {
	DatasetID      int64               `json:"dataset_id"`
	Normalizer     string              `json:"normalizer"`
	Snapshot       string              `json:"snapshot"`
	SourceKind     string              `json:"source_kind"`
	SourceSHA256   string              `json:"source_sha256"`
	From           string              `json:"from"`
	To             string              `json:"to"`
	EnvelopeOrigin string              `json:"envelope_origin"`
	Atomic         bool                `json:"atomic"`
	Before         governance.Identity `json:"before"`
	After          governance.Identity `json:"after"`
	Calls          []GovernanceCall    `json:"calls"`
	Operations     *int64              `json:"operations"`
	Faults         *int64              `json:"faults"`
	Gaps           *int64              `json:"gaps"`
}

func GovernanceInfo(id int64, kind, sourceSHA string, snap governance.Snapshot) (GovernanceCapture, error) {
	out := GovernanceCapture{DatasetID: id, Normalizer: governance.Normalizer, SourceKind: kind, SourceSHA256: sourceSHA, From: snap.From, To: snap.To, EnvelopeOrigin: snap.EnvelopeOrigin, Atomic: snap.Atomic, Before: snap.Before, After: snap.After, Calls: []GovernanceCall{}}
	if !oneSourceKind(kind) || len(sourceSHA) != 64 {
		return out, errors.New("invalid governance provenance")
	}
	if _, err := hex.DecodeString(sourceSHA); err != nil {
		return out, errors.New("invalid governance source hash")
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return out, err
	}
	sum := sha256.Sum256(raw)
	out.Snapshot = hex.EncodeToString(sum[:])
	for _, call := range snap.Calls {
		out.Calls = append(out.Calls, GovernanceCall{Ordinal: call.Ordinal, Request: call.Request, Status: call.Status, ErrorCode: call.ErrorCode, SHA256: call.SHA256})
		if call.Status != "available" {
			continue
		}
		switch call.Request.Method {
		case "wbft_govOps":
			var ops []governance.Operation
			if json.Unmarshal(call.Data, &ops) != nil {
				return out, errors.New("invalid normalized governance operations")
			}
			n := int64(len(ops))
			out.Operations = &n
		case "wbft_mirrorFaults":
			var rows []governance.Fault
			if json.Unmarshal(call.Data, &rows) != nil {
				return out, errors.New("invalid normalized governance faults")
			}
			n, gaps := int64(len(rows)), int64(0)
			for _, row := range rows {
				if row.Kind == "gap" {
					gaps++
				}
			}
			out.Faults, out.Gaps = &n, &gaps
		}
	}
	return out, nil
}

func (s *Store) BeginGovernance(ctx context.Context, key NetworkKey, name string, meta json.RawMessage) (Dataset, func(), error) {
	return s.beginDataset(ctx, key, name, "governance", meta)
}

// PutGovernance normalizes again at the persistence boundary. Original opaque
// envelopes are never stored, and every derived row retains its request scope.
// The complete capture, derived rows, and completed progress commit together.
func (s *Store) PutGovernance(ctx context.Context, id int64, kind, sourceSHA string, archive governance.Archive) (GovernanceCapture, error) {
	snap, err := governance.Normalize(archive)
	if err != nil {
		return GovernanceCapture{}, err
	}
	info, err := GovernanceInfo(id, kind, sourceSHA, snap)
	if err != nil {
		return info, err
	}
	rawInfo, err := json.Marshal(info)
	if err != nil {
		return info, err
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var datasetKind, chain, genesis string
		if err := tx.QueryRow(ctx, `SELECT d.kind,n.chain_id,n.genesis_hash FROM datasets d JOIN networks n ON n.id=d.network_id WHERE d.id=$1 FOR UPDATE OF d`, id).Scan(&datasetKind, &chain, &genesis); err != nil {
			return err
		}
		if datasetKind != "governance" || chain != snap.Before.ChainID || genesis != snap.Before.GenesisHash {
			return errors.New("governance dataset identity mismatch")
		}
		tag, err := tx.Exec(ctx, `INSERT INTO governance_captures(dataset_id,node,snapshot,info) VALUES($1,$2,$3,$4) ON CONFLICT(dataset_id) DO UPDATE SET snapshot=governance_captures.snapshot WHERE governance_captures.snapshot=EXCLUDED.snapshot AND governance_captures.info=EXCLUDED.info`, id, snap.Before.Address, info.Snapshot, rawInfo)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("governance source content conflict")
		}
		batch := &pgx.Batch{}
		for _, call := range snap.Calls {
			raw, err := json.Marshal(call)
			if err != nil {
				return err
			}
			batch.Queue(`INSERT INTO governance_calls(dataset_id,ordinal,method,call) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, id, call.Ordinal, call.Request.Method, raw)
			if call.Status == "available" {
				if err := queueGovernance(batch, id, call); err != nil {
					return err
				}
			}
		}
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE datasets SET status='complete',progress=$2,error='',updated_at=now() WHERE id=$1`, id, len(snap.Calls))
		return err
	})
	return info, err
}

func governanceIndex(value string) (string, error) {
	if !strings.HasPrefix(value, "0x") {
		return "", errors.New("invalid governance index")
	}
	n, err := strconv.ParseUint(value[2:], 16, 64)
	if err != nil {
		return "", errors.New("invalid governance index")
	}
	return strconv.FormatUint(n, 10), nil
}

func queueGovernance(batch *pgx.Batch, id int64, call governance.Call) error {
	switch call.Request.Method {
	case "wbft_govOps":
		var ops []governance.Operation
		if json.Unmarshal(call.Data, &ops) != nil {
			return errors.New("invalid normalized operations")
		}
		for i, op := range ops {
			if err := queueGovernanceOp(batch, id, call.Ordinal, i+1, strconv.Itoa(i), op); err != nil {
				return err
			}
		}
	case "wbft_mirrorFaults":
		var rows []governance.Fault
		if json.Unmarshal(call.Data, &rows) != nil {
			return errors.New("invalid normalized faults")
		}
		for i, row := range rows {
			n, err := governanceIndex(row.Number)
			if err != nil {
				return err
			}
			var from, to any
			if row.BoundsKnown {
				from, err = governanceIndex(*row.GapFrom)
				if err != nil {
					return err
				}
				to, err = governanceIndex(*row.GapTo)
				if err != nil {
					return err
				}
			}
			raw, err := json.Marshal(row)
			if err != nil {
				return err
			}
			batch.Queue(`INSERT INTO gov_gaps(dataset_id,call_ordinal,ordinal,number,kind,gap_from,gap_to,row_) VALUES($1,$2,$3,$4::numeric,$5,$6::numeric,$7::numeric,$8) ON CONFLICT DO NOTHING`, id, call.Ordinal, i+1, n, row.Kind, from, to, raw)
		}
	case "wbft_mirrorState":
		var row governance.State
		if json.Unmarshal(call.Data, &row) != nil {
			return errors.New("invalid normalized state")
		}
		n, err := governanceIndex(row.Number)
		if err != nil {
			return err
		}
		batch.Queue(`INSERT INTO gov_states(dataset_id,call_ordinal,number,instance,row_) VALUES($1,$2,$3::numeric,$4,$5) ON CONFLICT DO NOTHING`, id, call.Ordinal, n, row.Instance, call.Data)
	case "wbft_govProposal":
		var row governance.ProposalHistory
		if json.Unmarshal(call.Data, &row) != nil {
			return errors.New("invalid normalized proposal")
		}
		n, err := governanceIndex(row.ID)
		if err != nil {
			return err
		}
		for i, op := range row.Ops {
			if err := queueGovernanceOp(batch, id, call.Ordinal, i+1, fmt.Sprintf("ops/%d", i), op); err != nil {
				return err
			}
		}
		row.Ops = nil // Operations are indexed separately; the original call retains them.
		raw, err := json.Marshal(row)
		if err != nil {
			return err
		}
		batch.Queue(`INSERT INTO gov_proposals(dataset_id,call_ordinal,instance,proposal_id,row_) VALUES($1,$2,$3,$4::numeric,$5) ON CONFLICT DO NOTHING`, id, call.Ordinal, row.Instance, n, raw)
	case "wbft_validatorChanges":
		var rows []governance.ValidatorChange
		if json.Unmarshal(call.Data, &rows) != nil {
			return errors.New("invalid normalized validator changes")
		}
		ordinal := 0
		for i, row := range rows {
			n, err := governanceIndex(row.Number)
			if err != nil {
				return err
			}
			for j, op := range row.Ops {
				ordinal++
				if err := queueGovernanceOp(batch, id, call.Ordinal, ordinal, fmt.Sprintf("%d/ops/%d", i, j), op); err != nil {
					return err
				}
			}
			row.Ops = nil
			raw, err := json.Marshal(row)
			if err != nil {
				return err
			}
			batch.Queue(`INSERT INTO gov_validator_changes(dataset_id,call_ordinal,ordinal,number,row_) VALUES($1,$2,$3,$4::numeric,$5) ON CONFLICT DO NOTHING`, id, call.Ordinal, i+1, n, raw)
		}
	}
	return nil
}

func queueGovernanceOp(batch *pgx.Batch, id int64, call, ordinal int, path string, op governance.Operation) error {
	n, err := governanceIndex(op.Number)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(op)
	if err != nil {
		return err
	}
	batch.Queue(`INSERT INTO gov_ops(dataset_id,call_ordinal,ordinal,source_path,number,instance,tx_index,row_) VALUES($1,$2,$3,$4,$5::numeric,$6,$7,$8) ON CONFLICT DO NOTHING`, id, call, ordinal, path, n, op.Instance, int64(op.Tx), raw)
	return nil
}

func (s *Store) GovernanceCapture(ctx context.Context, id int64) (GovernanceCapture, error) {
	var out GovernanceCapture
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT c.info FROM governance_captures c JOIN datasets d ON d.id=c.dataset_id WHERE c.dataset_id=$1 AND d.status='complete'`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(raw, &out)
	return out, err
}

func (s *Store) GovernanceCall(ctx context.Context, id int64, ordinal int) (governance.Call, error) {
	var out governance.Call
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT c.call FROM governance_calls c JOIN datasets d ON d.id=c.dataset_id WHERE c.dataset_id=$1 AND c.ordinal=$2 AND d.status='complete'`, id, ordinal).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(raw, &out)
	return out, err
}
