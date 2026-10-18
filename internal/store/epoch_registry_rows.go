package store

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/privacy"
	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/0xmhha/wbft/types"
	"github.com/jackc/pgx/v5"
)

type epochRegistrySource struct {
	witness GovernanceTransitionWitness
	replay  GovernanceExecutionWitness
	capture GovernanceCapture
	report  executionwitness.TransitionReport
	name    string
	node    string
	binding string
}

func loadEpochRegistrySource(ctx context.Context, tx pgx.Tx, network, dataset int64, snapshot string) (*epochRegistrySource, error) {
	source := &epochRegistrySource{binding: "source_unavailable"}
	var raw, execution []byte
	var executionSnapshot string
	var original int64
	var header *int64
	err := tx.QueryRow(ctx, `SELECT d.name,c.node,w.execution_snapshot,w.info,e.info,e.header_dataset_id,e.header_source_id
 FROM governance_transition_witnesses w JOIN governance_execution_witnesses e ON e.dataset_id=w.dataset_id AND e.snapshot=w.execution_snapshot
 JOIN datasets d ON d.id=w.dataset_id JOIN networks n ON n.id=d.network_id JOIN governance_captures c ON c.dataset_id=d.id
 WHERE d.network_id=$1 AND w.dataset_id=$2 AND w.snapshot=$3 AND d.kind='governance' AND d.status='complete' AND d.visibility=$4 AND n.visibility=$4`, network, dataset, snapshot, privacy.Visibility()).Scan(&source.name, &source.node, &executionSnapshot, &raw, &execution, &header, &original)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &source.witness) != nil || json.Unmarshal(execution, &source.replay) != nil || source.witness.DatasetID != dataset || source.witness.Snapshot != snapshot || source.witness.ExecutionSnapshot != executionSnapshot || source.replay.DatasetID != dataset || source.replay.Snapshot != executionSnapshot || source.replay.HeaderSourceID != original {
		return nil, ErrGovernanceTransitionBinding
	}
	source.replay.HeadersDataset = header
	actualNetwork, capture, err := executionCapture(ctx, tx, dataset, false)
	if err != nil {
		return nil, err
	}
	source.capture = capture
	if actualNetwork == network && executionIdentity(capture, source.replay.Source.Report.Source) {
		source.binding, err = bindExecutionHeaders(ctx, tx, network, source.replay)
		if err != nil {
			return nil, err
		}
	}
	source.report, err = storedEpochTransitionReport(ctx, tx, source.witness, source.replay)
	if err != nil {
		return nil, err
	}
	return source, nil
}

func epochRegistryRow(ctx context.Context, tx pgx.Tx, network int64, index string, epoch *types.EpochInfo, position epochRegistryPosition, source *epochRegistrySource) (EpochRegistryRow, error) {
	row := EpochRegistryRow{Kind: "epoch_state", DatasetID: source.witness.DatasetID, DatasetName: source.name, Node: source.node, CaptureSnapshot: source.capture.Snapshot, WitnessSnapshot: source.witness.Snapshot, ExecutionSnapshot: source.replay.Snapshot, HeaderSourceID: source.replay.HeaderSourceID, HeadersDataset: source.replay.HeadersDataset, Verifier: source.replay.Source.Verifier, ConfigSHA256: source.replay.Source.Report.Source.ConfigSHA256, Binding: source.binding, Status: "unverified", Reason: "source_unbound", EpochHeaderStatus: "unavailable", Operations: []EpochRegistryOperation{}}
	n, err := strconv.ParseUint(index, 10, 64)
	if err != nil || n >= uint64(len(source.report.Blocks)) {
		return row, ErrGovernanceTransitionBinding
	}
	block := source.report.Blocks[n]
	read := block.EpochRegistry
	if n == 0 {
		row.EpochHeaderStatus = "not_compared_genesis"
	} else if read != nil && read.Status == "observed" {
		row.EpochHeaderStatus = "mismatch"
		if executionwitness.EpochRegistryMatches(epoch, *read) {
			row.EpochHeaderStatus = "matched"
		}
	}
	if position.kind == 0 {
		row.Registry = read
		if row.Binding != "matched" {
			return row, nil
		}
		row.Reason = "registry_unavailable"
		if read == nil || read.Status != "observed" {
			return row, nil
		}
		if n == 0 {
			row.Status, row.Reason = "matched", "initial_registry_state"
		} else if row.EpochHeaderStatus == "matched" {
			row.Status, row.Reason = "matched", "header_state_only"
		} else {
			row.Reason = "epoch_header_mismatch"
		}
		return row, nil
	}
	if position.kind != 1 {
		return row, ErrGovernanceTransitionBinding
	}
	row.Kind = "transaction_effect"
	pointIndex := -1
	for i, point := range source.report.Transactions {
		if point.Index == position.index && point.Ordinal == position.transaction {
			pointIndex = i
			break
		}
	}
	if pointIndex < 0 || position.effect < 0 || position.effect >= len(source.report.Transactions[pointIndex].Effects) {
		return row, ErrGovernanceTransitionBinding
	}
	point := source.report.Transactions[pointIndex]
	row.Effect = &EpochRegistryEffect{Index: point.Index, Transaction: point.Ordinal, Hash: point.Hash, Ordinal: position.effect, Change: point.Effects[position.effect], Retention: executionwitness.TrackEpochEffect(source.report, pointIndex, position.effect, index, epoch)}
	operationReason, err := epochRegistryOperations(ctx, tx, network, source, source.report.Execution.Transactions[pointIndex], &row)
	if err != nil {
		return row, err
	}
	if row.Binding != "matched" {
		return row, nil
	}
	row.Reason = "epoch_header_mismatch"
	if row.EpochHeaderStatus != "matched" {
		return row, nil
	}
	row.Reason = "retention_unverified"
	if row.Effect.Retention.Status != "verified_retained_registry_effect" {
		return row, nil
	}
	row.Reason = operationReason
	if operationReason == "verified_retained_registry_effect" {
		row.Status = "verified_retained_registry_effect"
	}
	return row, nil
}
