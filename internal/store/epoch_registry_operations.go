package store

import (
	"context"
	"encoding/json"

	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/jackc/pgx/v5"
)

func epochRegistryOperations(ctx context.Context, tx pgx.Tx, network int64, source *epochRegistrySource, point executionwitness.Transaction, result *EpochRegistryRow) (string, error) {
	type entry struct {
		ref EpochRegistryOperation
		op  governance.Operation
	}
	rows, err := tx.Query(ctx, `SELECT call_ordinal,ordinal,source_path,row_ FROM gov_ops
 WHERE dataset_id=$1 AND number=$2::numeric AND tx_index=$3 AND instance=$4 AND row_->'path'='[]'::jsonb
 ORDER BY call_ordinal,ordinal LIMIT 21`, source.witness.DatasetID, point.Index, point.Ordinal, point.To)
	if err != nil {
		return "operation_unavailable", err
	}
	entries := []entry{}
	for rows.Next() {
		var value entry
		var raw []byte
		if err := rows.Scan(&value.ref.CallOrdinal, &value.ref.EntryOrdinal, &value.ref.Pointer, &raw); err != nil {
			rows.Close()
			return "operation_unavailable", err
		}
		if json.Unmarshal(raw, &value.op) != nil {
			rows.Close()
			return "operation_unavailable", ErrGovernanceTransitionBinding
		}
		value.ref.Pointer = "/data/" + value.ref.Pointer
		value.ref.Status = "unverified"
		entries = append(entries, value)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "operation_unavailable", err
	}
	if len(entries) > 20 {
		entries = entries[:20]
		result.OperationsTruncated = true
	}
	reason := "verified_retained_registry_effect"
	if len(entries) == 0 {
		reason = "operation_unavailable"
	}
	for _, value := range entries {
		ref := value.ref
		if ref.CallOrdinal > 0 && ref.CallOrdinal <= len(source.capture.Calls) {
			call := source.capture.Calls[ref.CallOrdinal-1]
			if call.Ordinal == ref.CallOrdinal && call.Status == "available" && GovernanceCollection(call.Request.Method, "operations") {
				comparison, err := governanceTransitionEvidence(ctx, tx, network, source.witness.DatasetID, point.Index, &value.op)
				if err != nil {
					return "operation_unavailable", err
				}
				ref.ComparisonsTruncated = comparison.Truncated
				owned := false
				for _, witness := range comparison.Evidence {
					if witness.Witness.Snapshot == source.witness.Snapshot && witness.Binding == "matched" && witness.Status == "matched" && witness.CauseStatus == "verified_transaction_effect" {
						owned = true
					}
				}
				switch {
				case comparison.Truncated || comparison.Status == "ambiguous" || comparison.CauseStatus == "ambiguous":
					ref.Status = "ambiguous"
				case comparison.Status == "mismatch":
					ref.Status = "mismatch"
				case comparison.Status == "matched" && comparison.CauseStatus == "verified_transaction_effect" && owned:
					ref.Status = "matched"
				}
			}
		}
		if ref.Status != "matched" {
			switch ref.Status {
			case "ambiguous":
				reason = "operation_ambiguous"
			case "mismatch":
				if reason != "operation_ambiguous" {
					reason = "operation_mismatch"
				}
			default:
				if reason == "verified_retained_registry_effect" {
					reason = "operation_unverified"
				}
			}
		}
		result.Operations = append(result.Operations, ref)
	}
	if result.OperationsTruncated {
		reason = "operation_ambiguous"
	}
	return reason, nil
}
