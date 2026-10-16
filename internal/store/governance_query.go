package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/jackc/pgx/v5"
)

var ErrGovernanceQuery = errors.New("invalid governance request scope or collection")

// Proposal and change summaries omit their separately paginated operations.
type GovernanceProposalState struct {
	Instance string               `json:"instance"`
	ID       string               `json:"id"`
	Proposal *governance.Proposal `json:"proposal"`
}
type GovernanceChange struct {
	Number             string            `json:"number"`
	Validators         []string          `json:"validators"`
	ValidatorsReported bool              `json:"validators_reported"`
	Epoch              *governance.Epoch `json:"epoch"`
}
type GovernanceEntry struct {
	CallOrdinal int                      `json:"call_ordinal"`
	Ordinal     int                      `json:"ordinal"`
	Pointer     string                   `json:"normalized_pointer"`
	Operation   *governance.Operation    `json:"operation,omitempty"`
	Fault       *governance.Fault        `json:"fault,omitempty"`
	State       *governance.State        `json:"state,omitempty"`
	Proposal    *GovernanceProposalState `json:"proposal,omitempty"`
	Change      *GovernanceChange        `json:"change,omitempty"`
	Mirror      *governance.Mirror       `json:"mirror,omitempty"`
}

// GovernanceCollection validates the original RPC scope before selecting rows.
func GovernanceCollection(method, collection string) bool {
	switch collection {
	case "operations":
		return method == "wbft_govOps" || method == "wbft_govProposal" || method == "wbft_validatorChanges"
	case "faults":
		return method == "wbft_mirrorFaults"
	case "states":
		return method == "wbft_mirrorState"
	case "proposals":
		return method == "wbft_govProposal"
	case "changes":
		return method == "wbft_validatorChanges"
	case "mirrors":
		return method == "wbft_mirror"
	}
	return false
}

// GovernanceEntries returns one original request's rows in a consistent snapshot.
// Completion and the immutable capture hash fence the count and page together.
func (s *Store) GovernanceEntries(ctx context.Context, id int64, call int, collection string, offset int64, limit int) (entries []GovernanceEntry, total int64, err error) {
	entries = []GovernanceEntry{}
	if call < 1 || offset < 0 || limit < 1 || limit > 500 {
		return entries, 0, ErrGovernanceQuery
	}
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT c.info FROM governance_captures c JOIN datasets d ON d.id=c.dataset_id WHERE c.dataset_id=$1 AND d.status='complete'`, id).Scan(&raw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var info GovernanceCapture
		if err := json.Unmarshal(raw, &info); err != nil {
			return err
		}
		if call > len(info.Calls) || info.Calls[call-1].Ordinal != call || !GovernanceCollection(info.Calls[call-1].Request.Method, collection) {
			return ErrGovernanceQuery
		}
		if info.Calls[call-1].Status != "available" {
			if offset != 0 {
				return ErrGovernanceQuery
			}
			return nil
		}
		// SQL identifiers and projections come only from this fixed allowlist.
		var table, ordinal, path, value, scope string
		ordinal, path, value, scope = "ordinal", "''", "row_", "dataset_id=$1 AND call_ordinal=$2"
		switch collection {
		case "operations":
			table, path = "gov_ops", "source_path"
		case "faults":
			table = "gov_gaps"
		case "states":
			table, ordinal = "gov_states", "1"
		case "proposals":
			table, ordinal = "gov_proposals", "1"
		case "changes":
			table = "gov_validator_changes"
		case "mirrors":
			table, ordinal, value, scope = "governance_calls", "1", "call->'data'", "dataset_id=$1 AND ordinal=$2"
		default:
			return ErrGovernanceQuery
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE `+scope, id, call).Scan(&total); err != nil {
			return err
		}
		if offset > total {
			return ErrGovernanceQuery
		}
		rows, err := tx.Query(ctx, `SELECT `+ordinal+` AS row_ordinal,`+path+`,`+value+` FROM `+table+` WHERE `+scope+` ORDER BY row_ordinal LIMIT $3 OFFSET $4`, id, call, limit+1, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n int
			var sourcePath string
			var raw []byte
			if err := rows.Scan(&n, &sourcePath, &raw); err != nil {
				return err
			}
			entry := GovernanceEntry{CallOrdinal: call, Ordinal: n, Pointer: "/data"}
			var target any
			switch collection {
			case "operations":
				entry.Pointer += "/" + sourcePath
				entry.Operation = &governance.Operation{}
				target = entry.Operation
			case "faults":
				entry.Pointer += "/" + strconv.Itoa(n-1)
				entry.Fault = &governance.Fault{}
				target = entry.Fault
			case "states":
				entry.State = &governance.State{}
				target = entry.State
			case "proposals":
				entry.Proposal = &GovernanceProposalState{}
				target = entry.Proposal
			case "changes":
				entry.Pointer += "/" + strconv.Itoa(n-1)
				entry.Change = &GovernanceChange{}
				target = entry.Change
			case "mirrors":
				entry.Mirror = &governance.Mirror{}
				target = entry.Mirror
			}
			if err := json.Unmarshal(raw, target); err != nil {
				return err
			}
			entries = append(entries, entry)
		}
		return rows.Err()
	})
	return entries, total, err
}
