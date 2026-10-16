package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/jackc/pgx/v5"
)

// HeaderGovernanceClaims identifies exact-hash source claims, never execution
// causes. An empty or truncated list cannot establish complete history.
type HeaderGovernanceClaims struct {
	Index       string                  `json:"index"`
	Number      string                  `json:"number"`
	Hash        string                  `json:"hash"`
	Claims      []HeaderGovernanceClaim `json:"claims"`
	Truncated   bool                    `json:"truncated"`
	CauseStatus string                  `json:"cause_status" enum:"unestablished"`
}

type HeaderGovernanceClaim struct {
	DatasetID    int64                    `json:"dataset_id"`
	DatasetName  string                   `json:"dataset_name"`
	Node         string                   `json:"node"`
	Snapshot     string                   `json:"snapshot"`
	CallOrdinal  int                      `json:"call_ordinal"`
	EntryOrdinal int                      `json:"entry_ordinal"`
	Pointer      string                   `json:"normalized_pointer"`
	Epoch        *GovernanceEpochEvidence `json:"epoch"`
}

func (s *Store) HeaderGovernanceClaims(ctx context.Context, network int64, index string) (result HeaderGovernanceClaims, err error) {
	result = HeaderGovernanceClaims{Index: index, Claims: []HeaderGovernanceClaim{}, CauseStatus: "unestablished"}
	n, e := strconv.ParseUint(index, 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != index {
		return result, ErrGovernanceQuery
	}
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT hash,fact FROM heights WHERE network_id=$1 AND index_=$2::numeric`, network, index).Scan(&result.Hash, &raw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var fact headers.Fact
		if err := json.Unmarshal(raw, &fact); err != nil {
			return err
		}
		if fact.Index != index || fact.Hash != result.Hash {
			return errors.New("inconsistent canonical header fact")
		}
		result.Number = fact.Number
		rows, err := tx.Query(ctx, `SELECT d.id,d.name,c.node,c.snapshot,g.call_ordinal,g.ordinal,g.row_ FROM gov_validator_changes g JOIN datasets d ON d.id=g.dataset_id JOIN governance_captures c ON c.dataset_id=d.id WHERE d.network_id=$1 AND d.kind='governance' AND d.status='complete' AND g.number=$2::numeric AND lower(g.row_->>'block_hash')=lower($3) ORDER BY d.id,g.call_ordinal,g.ordinal LIMIT 21`, network, index, result.Hash)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var claim HeaderGovernanceClaim
			var raw []byte
			if err := rows.Scan(&claim.DatasetID, &claim.DatasetName, &claim.Node, &claim.Snapshot, &claim.CallOrdinal, &claim.EntryOrdinal, &raw); err != nil {
				return err
			}
			var change GovernanceChange
			if err := json.Unmarshal(raw, &change); err != nil {
				return err
			}
			claim.Pointer = "/data/" + strconv.Itoa(claim.EntryOrdinal-1)
			if change.Epoch != nil {
				claim.Epoch = compareGovernanceEpoch(fact, *change.Epoch)
			}
			result.Claims = append(result.Claims, claim)
		}
		if len(result.Claims) > 20 {
			result.Claims = result.Claims[:20]
			result.Truncated = true
		}
		return rows.Err()
	})
	return result, err
}
