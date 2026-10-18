package store

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/jackc/pgx/v5"
)

type GovernanceTransitionEvidence struct {
	Witness     GovernanceTransitionWitness             `json:"witness"`
	Replay      GovernanceExecutionWitness              `json:"replay"`
	Block       executionwitness.BlockTransition        `json:"block"`
	Point       *executionwitness.TransactionTransition `json:"point"`
	Operation   *GovernanceExecutionEvidence            `json:"operation"`
	NextEpoch   *executionwitness.BlockTransition       `json:"next_epoch"`
	Binding     string                                  `json:"binding" enum:"matched,header_unavailable,header_mismatch,config_mismatch,network_mismatch,source_unavailable"`
	Status      string                                  `json:"status" enum:"unverified,matched,mismatch"`
	CauseStatus string                                  `json:"cause_status" enum:"unestablished,verified_transaction_effect"`
	Reason      string                                  `json:"reason" enum:"source_unbound,operation_unmatched,header_state_only,transaction_effect_unestablished,verified_transaction_effect"`
}

type GovernanceTransitionEvidenceList struct {
	Status      string                         `json:"status" enum:"unverified,matched,mismatch,ambiguous"`
	CauseStatus string                         `json:"cause_status" enum:"unestablished,verified_transaction_effect,ambiguous"`
	Evidence    []GovernanceTransitionEvidence `json:"evidence"`
	Truncated   bool                           `json:"truncated"`
}

func governanceTransitionEvidence(ctx context.Context, tx pgx.Tx, network, dataset int64, index string, op *governance.Operation) (GovernanceTransitionEvidenceList, error) {
	result := GovernanceTransitionEvidenceList{Status: "unverified", CauseStatus: "unestablished", Evidence: []GovernanceTransitionEvidence{}}
	selection := `NULL::jsonb,NULL::jsonb`
	joins := ""
	args := []any{dataset, index}
	if op != nil {
		selection = `p.point,x.point`
		joins = ` JOIN governance_transition_transactions p ON p.dataset_id=w.dataset_id AND p.snapshot=w.snapshot AND p.index_=b.index_ AND p.tx_ordinal=$3::bigint JOIN governance_execution_transactions x ON x.dataset_id=e.dataset_id AND x.snapshot=e.snapshot AND x.index_=p.index_ AND x.tx_ordinal=p.tx_ordinal`
		args = append(args, int64(op.Tx))
	}
	rows, err := tx.Query(ctx, `SELECT w.snapshot,w.execution_snapshot,w.info,b.block,e.info,e.header_dataset_id,e.header_source_id,`+selection+` FROM governance_transition_witnesses w JOIN governance_transition_blocks b ON b.dataset_id=w.dataset_id AND b.snapshot=w.snapshot JOIN governance_execution_witnesses e ON e.dataset_id=w.dataset_id AND e.snapshot=w.execution_snapshot`+joins+` WHERE w.dataset_id=$1 AND b.index_=$2::numeric ORDER BY w.snapshot LIMIT 21`, args...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var snapshot, execution string
		var raw, block, replay, point, operation []byte
		var header *int64
		var original int64
		if err = rows.Scan(&snapshot, &execution, &raw, &block, &replay, &header, &original, &point, &operation); err != nil {
			rows.Close()
			return result, err
		}
		entry := GovernanceTransitionEvidence{Binding: "source_unavailable", Status: "unverified", CauseStatus: "unestablished", Reason: "source_unbound"}
		if json.Unmarshal(raw, &entry.Witness) != nil || json.Unmarshal(block, &entry.Block) != nil || json.Unmarshal(replay, &entry.Replay) != nil || entry.Witness.DatasetID != dataset || entry.Witness.Snapshot != snapshot || entry.Witness.ExecutionSnapshot != execution || entry.Replay.DatasetID != dataset || entry.Replay.Snapshot != execution || entry.Replay.HeaderSourceID != original || entry.Block.Index != index || entry.Witness.Source.Report.Protocol != executionwitness.TransitionProtocol || !reflect.DeepEqual(entry.Witness.Source.Report.Execution, entry.Replay.Source.Report) || entry.Witness.Source.Verifier != entry.Replay.Source.Verifier {
			rows.Close()
			return result, ErrGovernanceTransitionBinding
		}
		entry.Replay.HeadersDataset = header
		if op != nil {
			entry.Point = &executionwitness.TransactionTransition{}
			entry.Operation = &GovernanceExecutionEvidence{Witness: entry.Replay, Binding: "source_unavailable", Status: "unverified", ErrorStatus: "unverified", Reason: "source_unbound"}
			if json.Unmarshal(point, entry.Point) != nil || json.Unmarshal(operation, &entry.Operation.Point) != nil || entry.Point.Index != index || entry.Point.Ordinal != int(op.Tx) || entry.Operation.Point.Index != index || entry.Operation.Point.Ordinal != int(op.Tx) || entry.Point.Hash != entry.Operation.Point.Hash || entry.Point.BlockHash != entry.Operation.Point.BlockHash {
				rows.Close()
				return result, ErrGovernanceTransitionBinding
			}
		}
		result.Evidence = append(result.Evidence, entry)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if len(result.Evidence) > 20 {
		result.Truncated = true
		result.Evidence = result.Evidence[:20]
	}
	actualNetwork, capture, err := executionCapture(ctx, tx, dataset, false)
	if err != nil {
		return result, err
	}
	if actualNetwork != network {
		return result, ErrNotFound
	}
	for i := range result.Evidence {
		entry := &result.Evidence[i]
		if !executionIdentity(capture, entry.Replay.Source.Report.Source) {
			continue
		}
		entry.Binding, err = bindExecutionHeaders(ctx, tx, network, entry.Replay)
		if err != nil {
			return result, err
		}
		if op != nil {
			entry.Operation.Binding = entry.Binding
			compareExecutionOperation(entry.Operation, *op)
			entry.Status = entry.Operation.Status
			if entry.Binding != "matched" {
				continue
			}
			entry.Reason = "operation_unmatched"
			if entry.Operation.Status == "matched" {
				entry.Reason = "transaction_effect_unestablished"
				if entry.Point.CauseStatus == "verified_transaction_effect" {
					entry.CauseStatus = "verified_transaction_effect"
					entry.Reason = "verified_transaction_effect"
				}
			}
		} else if entry.Binding == "matched" {
			entry.Status = "matched"
			entry.Reason = "header_state_only"
		}
		// The next epoch is an independently replayed header state, not a claim
		// that this transaction caused its selection or its full candidate set.
		if op != nil {
			var raw []byte
			err = tx.QueryRow(ctx, `SELECT block FROM governance_transition_blocks WHERE dataset_id=$1 AND snapshot=$2 AND index_>=$3::numeric AND block->'epoch_registry'<>'null'::jsonb ORDER BY index_ LIMIT 1`, dataset, entry.Witness.Snapshot, index).Scan(&raw)
			if err == nil {
				entry.NextEpoch = &executionwitness.BlockTransition{}
				if json.Unmarshal(raw, entry.NextEpoch) != nil {
					return result, ErrGovernanceTransitionBinding
				}
			} else if err != pgx.ErrNoRows {
				return result, err
			}
		}
	}
	summarizeTransitionEvidence(&result)
	return result, nil
}

func summarizeTransitionEvidence(result *GovernanceTransitionEvidenceList) {
	result.Status, result.CauseStatus = "unverified", "unestablished"
	if result.Truncated {
		result.Status, result.CauseStatus = "ambiguous", "ambiguous"
		return
	}
	if len(result.Evidence) == 0 {
		return
	}
	profiles := make(map[string]bool)
	for _, entry := range result.Evidence {
		var execution *executionwitness.Transaction
		if entry.Operation != nil {
			execution = &entry.Operation.Point
		}
		// Later epoch coverage is a separate observation. Its absence or a
		// longer source range cannot contradict an identical registry effect.
		raw, _ := json.Marshal(struct {
			Point     *executionwitness.TransactionTransition
			Block     executionwitness.BlockTransition
			Execution *executionwitness.Transaction
			Origin    executionwitness.Origin
			Config    string
		}{entry.Point, entry.Block, execution, entry.Replay.Source.Report.Origin, entry.Replay.Source.Report.Source.ConfigSHA256})
		profiles[string(raw)] = true
	}
	if len(profiles) != 1 {
		result.Status, result.CauseStatus = "ambiguous", "ambiguous"
		return
	}
	for _, entry := range result.Evidence {
		if entry.Binding != "matched" || entry.Status == "unverified" {
			return
		}
	}
	result.Status = result.Evidence[0].Status
	for _, entry := range result.Evidence {
		if entry.Status != "matched" || entry.CauseStatus != "verified_transaction_effect" {
			return
		}
	}
	result.CauseStatus = "verified_transaction_effect"
}
