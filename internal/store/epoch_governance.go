package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/privacy"
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
		if err := tx.QueryRow(ctx, `SELECT h.hash,h.fact FROM heights h JOIN networks n ON n.id=h.network_id WHERE h.network_id=$1 AND h.index_=$2::numeric AND n.visibility=$3`, network, index, privacy.Visibility()).Scan(&result.Hash, &raw); err != nil {
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
		rows, err := tx.Query(ctx, `SELECT d.id,d.name,c.node,c.snapshot,g.call_ordinal,g.ordinal,g.row_ FROM gov_validator_changes g JOIN datasets d ON d.id=g.dataset_id JOIN governance_captures c ON c.dataset_id=d.id WHERE d.network_id=$1 AND d.kind='governance' AND d.status='complete' AND d.visibility=$4 AND g.number=$2::numeric AND lower(g.row_->>'block_hash')=lower($3) ORDER BY d.id,g.call_ordinal,g.ordinal LIMIT 21`, network, index, result.Hash, privacy.Visibility())
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
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for i := range result.Claims {
			claim := &result.Claims[i]
			if claim.Epoch == nil {
				continue
			}
			var raw []byte
			if err := tx.QueryRow(ctx, `SELECT row_ FROM gov_validator_changes WHERE dataset_id=$1 AND call_ordinal=$2 AND ordinal=$3`, claim.DatasetID, claim.CallOrdinal, claim.EntryOrdinal).Scan(&raw); err != nil {
				return err
			}
			var change GovernanceChange
			if json.Unmarshal(raw, &change) != nil || change.Epoch == nil {
				return ErrStateWitnessBinding
			}
			evidence, err := governanceStateEvidence(ctx, tx, network, claim.DatasetID, index)
			if err != nil {
				return err
			}
			applyGovernanceState(claim.Epoch, *change.Epoch, evidence)
		}
		return nil
	})
	return result, err
}
