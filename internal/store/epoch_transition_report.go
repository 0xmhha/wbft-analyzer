package store

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/jackc/pgx/v5"
)

// storedEpochTransitionReport reconstructs only the immutable, originally
// admitted replay. It does not authenticate the current canonical headers or a
// governance operation. Readers must check those original dependencies as well.
func storedEpochTransitionReport(ctx context.Context, tx pgx.Tx, witness GovernanceTransitionWitness, replay GovernanceExecutionWitness) (executionwitness.TransitionReport, error) {
	report := witness.Source.Report
	if witness.DatasetID != replay.DatasetID || witness.ExecutionSnapshot != replay.Snapshot || witness.Blocks != replay.Blocks || witness.Transactions != replay.Transactions || witness.Blocks < 1 || witness.Blocks > executionwitness.MaxBlocks || witness.Transactions < 0 || witness.Transactions > executionwitness.MaxTransactions || report.Protocol != executionwitness.TransitionProtocol || report.Execution.Protocol != executionwitness.Protocol || !reflect.DeepEqual(report.Execution, replay.Source.Report) || witness.Source.Verifier != replay.Source.Verifier {
		return report, ErrGovernanceTransitionBinding
	}
	report.Blocks = []executionwitness.BlockTransition{}
	report.Transactions = []executionwitness.TransactionTransition{}
	report.Execution.Source.Blocks = []executionwitness.BlockEvidence{}
	report.Execution.Transactions = []executionwitness.Transaction{}
	// JSONB adds insignificant whitespace to the bounded helper projection.
	// Limit the reconstruction without multiplying its size by the source count.
	remaining := 2 * executionwitness.MaxProjectionBytes
	decode := func(raw []byte, into any) bool {
		if len(raw) == 0 || len(raw) > remaining {
			return false
		}
		remaining -= len(raw)
		return json.Unmarshal(raw, into) == nil
	}
	rows, err := tx.Query(ctx, `SELECT COALESCE(b.index_,e.index_)::text,b.block,e.block
 FROM (SELECT index_,block FROM governance_transition_blocks WHERE dataset_id=$1 AND snapshot=$2) b
 FULL JOIN (SELECT index_,block FROM governance_execution_blocks WHERE dataset_id=$1 AND snapshot=$3) e ON e.index_=b.index_
 ORDER BY COALESCE(b.index_,e.index_) LIMIT $4`, witness.DatasetID, witness.Snapshot, replay.Snapshot, witness.Blocks+1)
	if err != nil {
		return report, err
	}
	previous := ""
	for rows.Next() {
		var index string
		var raw, execution []byte
		if err = rows.Scan(&index, &raw, &execution); err != nil {
			rows.Close()
			return report, err
		}
		var block executionwitness.BlockTransition
		var source executionwitness.BlockEvidence
		count := len(report.Blocks)
		if count >= witness.Blocks || index != strconv.Itoa(count) || !decode(raw, &block) || !decode(execution, &source) || block.Index != index || source.Index != index || block.Genesis != (count == 0) || count > 0 && source.Parent != previous || count == 0 && source.Hash != replay.Source.Report.Source.GenesisHash {
			rows.Close()
			return report, ErrGovernanceTransitionBinding
		}
		report.Blocks = append(report.Blocks, block)
		report.Execution.Source.Blocks = append(report.Execution.Source.Blocks, source)
		previous = source.Hash
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return report, err
	}
	if len(report.Blocks) != witness.Blocks {
		return report, ErrGovernanceTransitionBinding
	}
	rows, err = tx.Query(ctx, `SELECT COALESCE(p.index_,e.index_)::text,COALESCE(p.tx_ordinal,e.tx_ordinal),p.point,e.point
 FROM (SELECT index_,tx_ordinal,point FROM governance_transition_transactions WHERE dataset_id=$1 AND snapshot=$2) p
 FULL JOIN (SELECT index_,tx_ordinal,point FROM governance_execution_transactions WHERE dataset_id=$1 AND snapshot=$3) e ON e.index_=p.index_ AND e.tx_ordinal=p.tx_ordinal
 ORDER BY COALESCE(p.index_,e.index_),COALESCE(p.tx_ordinal,e.tx_ordinal) LIMIT $4`, witness.DatasetID, witness.Snapshot, replay.Snapshot, witness.Transactions+1)
	if err != nil {
		return report, err
	}
	lastIndex, next := "", 0
	for rows.Next() {
		var index string
		var ordinal int
		var raw, execution []byte
		if err = rows.Scan(&index, &ordinal, &raw, &execution); err != nil {
			rows.Close()
			return report, err
		}
		var point executionwitness.TransactionTransition
		var source executionwitness.Transaction
		block, e := strconv.ParseUint(index, 10, 64)
		if index != lastIndex {
			next = 0
		}
		if e != nil || block == 0 || block >= uint64(witness.Blocks) || len(report.Transactions) >= witness.Transactions || ordinal != next || !decode(raw, &point) || !decode(execution, &source) || point.Index != index || source.Index != index || point.Ordinal != ordinal || source.Ordinal != ordinal || point.Hash != source.Hash || point.BlockHash != source.BlockHash || source.BlockHash != report.Execution.Source.Blocks[block].Hash {
			rows.Close()
			return report, ErrGovernanceTransitionBinding
		}
		report.Transactions = append(report.Transactions, point)
		report.Execution.Transactions = append(report.Execution.Transactions, source)
		lastIndex, next = index, next+1
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return report, err
	}
	if len(report.Transactions) != witness.Transactions {
		return report, ErrGovernanceTransitionBinding
	}
	return report, nil
}
