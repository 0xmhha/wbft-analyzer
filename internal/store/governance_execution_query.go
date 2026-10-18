package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/jackc/pgx/v5"
)

type GovernanceExecutionEvidence struct {
	Witness     GovernanceExecutionWitness   `json:"witness"`
	Point       executionwitness.Transaction `json:"point"`
	Binding     string                       `json:"binding" enum:"matched,header_unavailable,header_mismatch,config_mismatch,network_mismatch,source_unavailable"`
	Status      string                       `json:"status" enum:"unverified,matched,mismatch"`
	ErrorStatus string                       `json:"error_status" enum:"unverified,not_reported,matched,mismatch"`
	Reason      string                       `json:"reason" enum:"source_unavailable,source_unbound,nested_path_unmapped,source_hash_unavailable,identity_mismatch,outcome_mismatch,outcome_unavailable,logs_mismatch,matched"`
}
type GovernanceExecutionEvidenceList struct {
	Status      string                        `json:"status" enum:"unverified,matched,mismatch,ambiguous"`
	ErrorStatus string                        `json:"error_status" enum:"unverified,not_reported,matched,mismatch,ambiguous"`
	Evidence    []GovernanceExecutionEvidence `json:"evidence"`
	Truncated   bool                          `json:"truncated"`
}

func governanceExecutionEvidence(ctx context.Context, tx pgx.Tx, network, dataset int64, index string, op governance.Operation) (GovernanceExecutionEvidenceList, error) {
	result := GovernanceExecutionEvidenceList{Status: "unverified", ErrorStatus: "unverified", Evidence: []GovernanceExecutionEvidence{}}
	rows, err := tx.Query(ctx, `SELECT w.snapshot,w.header_dataset_id,w.header_source_id,w.info,p.point FROM governance_execution_transactions p JOIN governance_execution_witnesses w USING(dataset_id,snapshot) WHERE p.dataset_id=$1 AND p.index_=$2::numeric AND p.tx_ordinal=$3::bigint ORDER BY w.snapshot LIMIT 21`, dataset, index, int64(op.Tx))
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var snapshot string
		var header *int64
		var original int64
		var raw, point []byte
		if err := rows.Scan(&snapshot, &header, &original, &raw, &point); err != nil {
			rows.Close()
			return result, err
		}
		entry := GovernanceExecutionEvidence{Binding: "source_unavailable", Status: "unverified", ErrorStatus: "unverified", Reason: "source_unavailable"}
		if json.Unmarshal(raw, &entry.Witness) != nil || json.Unmarshal(point, &entry.Point) != nil || entry.Witness.DatasetID != dataset || entry.Witness.Snapshot != snapshot || entry.Witness.HeaderSourceID != original || entry.Point.Index != index || entry.Point.Ordinal != int(op.Tx) || len(entry.Point.Frames) == 0 {
			rows.Close()
			return result, ErrExecutionWitnessBinding
		}
		entry.Witness.HeadersDataset = header
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
	if errors.Is(err, ErrNotFound) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	if actualNetwork != network {
		return result, ErrNotFound
	}
	for i := range result.Evidence {
		entry := &result.Evidence[i]
		// The original normalized request owns each operation scope. Proposal
		// history can extend beyond the separate bounded govOps interval.
		if !executionIdentity(capture, entry.Witness.Source.Report.Source) {
			continue
		}
		entry.Binding, err = bindExecutionHeaders(ctx, tx, network, entry.Witness)
		if err != nil {
			return result, err
		}
		compareExecutionOperation(entry, op)
	}
	summarizeExecutionEvidence(&result)
	return result, nil
}

func sourceText(value string) governance.Bytes {
	sum := sha256.Sum256([]byte(value))
	return governance.Bytes{SHA256: hex.EncodeToString(sum[:]), Length: len(value)}
}
func sameExecutionBytes(a governance.Bytes, b executionwitness.Digest) bool {
	return a.SHA256 == b.SHA256 && a.Length == b.Bytes
}

func compareExecutionOperation(entry *GovernanceExecutionEvidence, op governance.Operation) {
	entry.Status, entry.ErrorStatus, entry.Reason = "unverified", "unverified", "source_unbound"
	if entry.Binding != "matched" {
		return
	}
	if len(op.Path) != 0 {
		entry.Reason = "nested_path_unmapped"
		return
	}
	if op.BlockHash == nil {
		entry.Reason = "source_hash_unavailable"
		return
	}
	point := entry.Point
	if len(point.Frames) == 0 {
		return
	}
	root := point.Frames[0]
	number, err := strconv.ParseUint(op.Number, 0, 64)
	if err != nil || strconv.FormatUint(number, 10) != point.Index || !strings.EqualFold(*op.BlockHash, point.BlockHash) || !strings.EqualFold(op.TxHash, point.Hash) || int(op.Tx) != point.Ordinal || op.From != point.From || op.Instance != point.To || !sameExecutionBytes(op.Input, point.Input) || op.Selector != point.Selector {
		entry.Status, entry.Reason = "mismatch", "identity_mismatch"
		return
	}
	success := point.ReceiptStatus == "succeeded"
	if op.Effective != success || op.View || success && (op.Result != "success" || op.ResultValue != sourceText("success")) || !success && op.Result == "success" {
		entry.Status, entry.Reason = "mismatch", "outcome_mismatch"
		return
	}
	if len(op.Logs) != len(point.Logs) {
		entry.Status, entry.Reason = "mismatch", "logs_mismatch"
		return
	}
	for i, log := range op.Logs {
		observed := point.Logs[i]
		if log.Address != observed.Address || !slices.Equal(log.Topics, observed.Topics) || !sameExecutionBytes(log.Data, observed.Data) {
			entry.Status, entry.Reason = "mismatch", "logs_mismatch"
			return
		}
	}
	entry.Status, entry.Reason = "matched", "matched"
	if success {
		entry.ErrorStatus = "not_reported"
		return
	}
	if root.ABIStatus == "decoded_revert" && root.ErrorName != "" {
		if op.ResultValue == sourceText(root.ErrorName) && (op.ErrorName == root.ErrorName || op.Result == "unknown" && op.ErrorName == "") {
			entry.ErrorStatus = "matched"
			return
		}
		if op.ErrorName != "" || op.ResultValue != sourceText("revert") {
			entry.ErrorStatus = "mismatch"
			entry.Status = "mismatch"
			entry.Reason = "outcome_mismatch"
			return
		}
	}
	if op.ErrorName != "" {
		entry.Status, entry.ErrorStatus, entry.Reason = "unverified", "unverified", "outcome_unavailable"
		return
	}
	if root.Status == "reverted" && op.Result == "revert" && op.ResultValue == sourceText("revert") {
		entry.ErrorStatus = "not_reported"
		return
	}
	entry.Status, entry.ErrorStatus, entry.Reason = "unverified", "unverified", "outcome_unavailable"
}

// A truncated or conflicting set cannot select a convenient latest witness.
// All attached sources must remain bound before a comparison becomes matched.
func summarizeExecutionEvidence(result *GovernanceExecutionEvidenceList) {
	result.Status, result.ErrorStatus = "unverified", "unverified"
	if result.Truncated {
		result.Status, result.ErrorStatus = "ambiguous", "ambiguous"
		return
	}
	if len(result.Evidence) == 0 {
		return
	}
	profiles := map[string]bool{}
	for _, entry := range result.Evidence {
		raw, _ := json.Marshal(struct {
			Point  executionwitness.Transaction
			Origin executionwitness.Origin
			Config string
		}{entry.Point, entry.Witness.Source.Report.Origin, entry.Witness.Source.Report.Source.ConfigSHA256})
		profiles[string(raw)] = true
	}
	if len(profiles) != 1 {
		result.Status, result.ErrorStatus = "ambiguous", "ambiguous"
		return
	}
	for _, entry := range result.Evidence {
		if entry.Binding != "matched" || entry.Status == "unverified" {
			return
		}
	}
	result.Status, result.ErrorStatus = result.Evidence[0].Status, result.Evidence[0].ErrorStatus
}
