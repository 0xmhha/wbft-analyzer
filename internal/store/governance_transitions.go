package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/jackc/pgx/v5"
)

var ErrGovernanceTransitionBinding = errors.New("governance transitions have no matching completed capture and canonical replay")

type GovernanceTransitionWitness struct {
	DatasetID         int64                                 `json:"dataset_id"`
	Snapshot          string                                `json:"snapshot"`
	ExecutionSnapshot string                                `json:"execution_snapshot"`
	Source            executionwitness.TransitionProjection `json:"source"`
	Blocks            int                                   `json:"blocks"`
	Transactions      int                                   `json:"transactions"`
}

// Replay and transitions commit together. The only public input is the opaque
// loader result; source annotations and previously attached evidence stay intact.
func (s *Store) PutGovernanceTransitions(ctx context.Context, dataset, headers int64, bundle executionwitness.TransitionBundle) (GovernanceTransitionWitness, error) {
	projection := bundle.Projection()
	if projection.Report.Protocol != executionwitness.TransitionProtocol || len(projection.Report.Blocks) != len(projection.Report.Execution.Source.Blocks) || len(projection.Report.Transactions) != len(projection.Report.Execution.Transactions) {
		return GovernanceTransitionWitness{}, ErrGovernanceTransitionBinding
	}
	raw, err := json.Marshal(struct {
		Header int64                                 `json:"headers_dataset"`
		Source executionwitness.TransitionProjection `json:"source"`
	}{headers, projection})
	if err != nil {
		return GovernanceTransitionWitness{}, err
	}
	sum := sha256.Sum256(raw)
	var result GovernanceTransitionWitness
	execution := executionwitness.Projection{Report: projection.Report.Execution, Verifier: projection.Verifier}
	_, err = s.putGovernanceExecutionWitness(ctx, dataset, headers, execution, func(ctx context.Context, tx pgx.Tx, verified GovernanceExecutionWitness) error {
		result = GovernanceTransitionWitness{DatasetID: dataset, Snapshot: hex.EncodeToString(sum[:]), ExecutionSnapshot: verified.Snapshot, Source: projection, Blocks: len(projection.Report.Blocks), Transactions: len(projection.Report.Transactions)}
		result.Source.Report.Execution.Source.Blocks = []executionwitness.BlockEvidence{}
		result.Source.Report.Execution.Transactions = []executionwitness.Transaction{}
		result.Source.Report.Blocks = []executionwitness.BlockTransition{}
		result.Source.Report.Transactions = []executionwitness.TransactionTransition{}
		info, err := json.Marshal(result)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO governance_transition_witnesses(dataset_id,snapshot,execution_snapshot,info) VALUES($1,$2,$3,$4) ON CONFLICT(dataset_id,snapshot) DO UPDATE SET snapshot=governance_transition_witnesses.snapshot WHERE governance_transition_witnesses.info=EXCLUDED.info AND governance_transition_witnesses.execution_snapshot=EXCLUDED.execution_snapshot`, dataset, result.Snapshot, verified.Snapshot, info)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrGovernanceTransitionBinding
		}
		for _, block := range projection.Report.Blocks {
			raw, err := json.Marshal(block)
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `INSERT INTO governance_transition_blocks(dataset_id,snapshot,index_,block) VALUES($1,$2,$3::numeric,$4) ON CONFLICT(dataset_id,snapshot,index_) DO UPDATE SET block=governance_transition_blocks.block WHERE governance_transition_blocks.block=EXCLUDED.block`, dataset, result.Snapshot, block.Index, raw)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return ErrGovernanceTransitionBinding
			}
		}
		for _, point := range projection.Report.Transactions {
			raw, err := json.Marshal(point)
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `INSERT INTO governance_transition_transactions(dataset_id,snapshot,index_,tx_ordinal,point) VALUES($1,$2,$3::numeric,$4,$5) ON CONFLICT(dataset_id,snapshot,index_,tx_ordinal) DO UPDATE SET point=governance_transition_transactions.point WHERE governance_transition_transactions.point=EXCLUDED.point`, dataset, result.Snapshot, point.Index, point.Ordinal, raw)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return ErrGovernanceTransitionBinding
			}
		}
		return nil
	})
	if err != nil {
		return GovernanceTransitionWitness{}, err
	}
	return result, nil
}
