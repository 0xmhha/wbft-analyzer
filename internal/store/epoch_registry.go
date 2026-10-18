package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/privacy"
	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft/types"
	"github.com/jackc/pgx/v5"
)

var ErrEpochRegistrySnapshot = errors.New("epoch registry evidence source set changed")

type EpochRegistryPage struct {
	Index    string             `json:"index"`
	Hash     string             `json:"hash"`
	Status   string             `json:"status" enum:"available,genesis,not_epoch"`
	Snapshot string             `json:"snapshot"`
	Rows     []EpochRegistryRow `json:"rows"`
	Total    int64              `json:"total"`
	Next     *int64             `json:"next"`
}

// Each row owns one original capture and replay. Retention is not an epoch-wide
// cause or a claim that the transaction selected a validator.
type EpochRegistryRow struct {
	Kind                string                         `json:"kind" enum:"epoch_state,transaction_effect"`
	DatasetID           int64                          `json:"dataset_id"`
	DatasetName         string                         `json:"dataset_name"`
	Node                string                         `json:"node"`
	CaptureSnapshot     string                         `json:"capture_snapshot"`
	WitnessSnapshot     string                         `json:"witness_snapshot"`
	ExecutionSnapshot   string                         `json:"execution_snapshot"`
	HeaderSourceID      int64                          `json:"header_source_id"`
	HeadersDataset      *int64                         `json:"headers_dataset"`
	Verifier            executionwitness.Verifier      `json:"verifier"`
	ConfigSHA256        string                         `json:"config_sha256"`
	Binding             string                         `json:"binding" enum:"matched,header_unavailable,header_mismatch,config_mismatch,network_mismatch,source_unavailable"`
	Status              string                         `json:"status" enum:"unverified,matched,verified_retained_registry_effect"`
	Reason              string                         `json:"reason" enum:"source_unbound,header_state_only,initial_registry_state,registry_unavailable,epoch_header_mismatch,retention_unverified,operation_unavailable,operation_unverified,operation_mismatch,operation_ambiguous,verified_retained_registry_effect"`
	EpochHeaderStatus   string                         `json:"epoch_header_status" enum:"matched,mismatch,unavailable,not_compared_genesis"`
	Registry            *executionwitness.RegistryRead `json:"registry"`
	Effect              *EpochRegistryEffect           `json:"effect"`
	Operations          []EpochRegistryOperation       `json:"operations"`
	OperationsTruncated bool                           `json:"operations_truncated"`
}

type EpochRegistryEffect struct {
	Index       string                              `json:"index"`
	Transaction int                                 `json:"transaction_index"`
	Hash        string                              `json:"hash"`
	Ordinal     int                                 `json:"effect_ordinal"`
	Change      executionwitness.RegistryEffect     `json:"change"`
	Retention   executionwitness.EpochEffectLineage `json:"retention"`
}

type EpochRegistryOperation struct {
	CallOrdinal          int    `json:"call_ordinal"`
	EntryOrdinal         int    `json:"entry_ordinal"`
	Pointer              string `json:"normalized_pointer"`
	Status               string `json:"status" enum:"matched,unverified,mismatch,ambiguous"`
	ComparisonsTruncated bool   `json:"comparisons_truncated"`
}

const epochRegistryRowsSQL = `WITH sources AS (
 SELECT w.dataset_id,w.snapshot,w.execution_snapshot,c.snapshot AS capture_snapshot,
 COALESCE((SELECT MAX(b.index_) FROM governance_transition_blocks b
 WHERE b.dataset_id=w.dataset_id AND b.snapshot=w.snapshot AND b.index_<$2::numeric
 AND b.block->'epoch_registry'<>'null'::jsonb),-1) AS preceding_epoch
 FROM governance_transition_witnesses w JOIN governance_execution_witnesses e
 ON e.dataset_id=w.dataset_id AND e.snapshot=w.execution_snapshot
 JOIN datasets d ON d.id=w.dataset_id JOIN networks n ON n.id=d.network_id
 JOIN governance_captures c ON c.dataset_id=d.id
 WHERE d.network_id=$1 AND d.kind='governance' AND d.status='complete'
 AND d.visibility=$3 AND n.visibility=$3 AND (w.info->>'blocks')::numeric>$2::numeric
), evidence_rows AS (
 SELECT dataset_id,snapshot,0 AS kind,$2::numeric AS index_,-1 AS tx_ordinal,-1::bigint AS effect_ordinal FROM sources
 UNION ALL
 SELECT s.dataset_id,s.snapshot,1,p.index_,p.tx_ordinal,a.ordinality-1 FROM sources s
 JOIN governance_transition_transactions p ON p.dataset_id=s.dataset_id AND p.snapshot=s.snapshot
 CROSS JOIN LATERAL jsonb_array_elements(p.point->'effects') WITH ORDINALITY a
 WHERE p.index_>s.preceding_epoch AND p.index_<=$2::numeric
) `

type epochRegistryPosition struct {
	dataset     int64
	snapshot    string
	kind        int
	index       string
	transaction int
	effect      int
}

func (s *Store) EpochRegistryEffects(ctx context.Context, network int64, index string, offset int64, limit int, expectedSnapshot string) (page EpochRegistryPage, err error) {
	page = EpochRegistryPage{Index: index, Status: "available", Rows: []EpochRegistryRow{}}
	n, failure := strconv.ParseUint(index, 10, 64)
	if failure != nil || strconv.FormatUint(n, 10) != index || network < 1 || offset < 0 || limit < 1 || limit > 20 {
		return page, ErrGovernanceQuery
	}
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT h.hash,h.fact FROM heights h JOIN networks n ON n.id=h.network_id WHERE h.network_id=$1 AND h.index_=$2::numeric AND n.visibility=$3`, network, index, privacy.Visibility()).Scan(&page.Hash, &raw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var fact headers.Fact
		if json.Unmarshal(raw, &fact) != nil || fact.Index != index || fact.Hash != page.Hash {
			return ErrGovernanceTransitionBinding
		}
		var epoch *types.EpochInfo
		if len(fact.EpochInfo) != 0 && string(fact.EpochInfo) != "null" {
			epoch = &types.EpochInfo{}
			if json.Unmarshal(fact.EpochInfo, epoch) != nil {
				return ErrGovernanceTransitionBinding
			}
		}
		hash := sha256.New()
		seed, _ := json.Marshal([]any{network, index, page.Hash})
		hash.Write(seed)
		if epoch == nil {
			page.Status = "not_epoch"
		} else {
			if n == 0 {
				page.Status = "genesis"
			}
			rows, err := tx.Query(ctx, epochRegistryRowsSQL+`SELECT s.dataset_id,s.snapshot,s.execution_snapshot,s.capture_snapshot,COUNT(*)
 FROM sources s JOIN evidence_rows r ON r.dataset_id=s.dataset_id AND r.snapshot=s.snapshot
 GROUP BY s.dataset_id,s.snapshot,s.execution_snapshot,s.capture_snapshot ORDER BY s.dataset_id,s.snapshot`, network, index, privacy.Visibility())
			if err != nil {
				return err
			}
			for rows.Next() {
				var id, count int64
				var snapshot, execution, capture string
				if err := rows.Scan(&id, &snapshot, &execution, &capture, &count); err != nil {
					rows.Close()
					return err
				}
				if count < 1 || count > math.MaxInt64-page.Total {
					rows.Close()
					return ErrGovernanceQuery
				}
				page.Total += count
				identity, _ := json.Marshal([]any{id, snapshot, execution, capture, count})
				hash.Write(identity)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
		}
		page.Snapshot = hex.EncodeToString(hash.Sum(nil))
		if expectedSnapshot != "" && page.Snapshot != expectedSnapshot {
			return ErrEpochRegistrySnapshot
		}
		if offset > page.Total {
			return ErrGovernanceQuery
		}
		if epoch == nil || offset == page.Total {
			return nil
		}
		rows, err := tx.Query(ctx, epochRegistryRowsSQL+`SELECT dataset_id,snapshot,kind,index_::text,tx_ordinal,effect_ordinal FROM evidence_rows
 ORDER BY dataset_id,snapshot,kind,index_,tx_ordinal,effect_ordinal OFFSET $4 LIMIT $5`, network, index, privacy.Visibility(), offset, limit+1)
		if err != nil {
			return err
		}
		positions := []epochRegistryPosition{}
		for rows.Next() {
			var p epochRegistryPosition
			if err := rows.Scan(&p.dataset, &p.snapshot, &p.kind, &p.index, &p.transaction, &p.effect); err != nil {
				rows.Close()
				return err
			}
			positions = append(positions, p)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(positions) > limit {
			next := offset + int64(limit)
			page.Next = &next
			positions = positions[:limit]
		}
		var source *epochRegistrySource
		for _, position := range positions {
			if source == nil || source.witness.DatasetID != position.dataset || source.witness.Snapshot != position.snapshot {
				source, err = loadEpochRegistrySource(ctx, tx, network, position.dataset, position.snapshot)
				if err != nil {
					return err
				}
			}
			row, err := epochRegistryRow(ctx, tx, network, index, epoch, position, source)
			if err != nil {
				return err
			}
			page.Rows = append(page.Rows, row)
		}
		return nil
	})
	return page, err
}
