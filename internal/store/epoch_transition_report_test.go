package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/jackc/pgx/v5"
)

// Persisted synthetic rows exercise structural reconstruction, not VM admission.
func TestStoredEpochTransitionReportRequiresCompleteOwnedRows(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	gov, _, replay, op := executionStoredFixture(t, s)
	witness := GovernanceTransitionWitness{DatasetID: gov.ID, Snapshot: strings.Repeat("d", 64), ExecutionSnapshot: replay.Snapshot, Source: executionwitness.TransitionProjection{Report: executionwitness.TransitionReport{Protocol: executionwitness.TransitionProtocol, Execution: replay.Source.Report}, Verifier: replay.Source.Verifier}, Blocks: replay.Blocks, Transactions: replay.Transactions}
	raw, _ := json.Marshal(witness)
	if _, err := s.pool.Exec(ctx, `INSERT INTO governance_transition_witnesses VALUES($1,$2,$3,$4)`, gov.ID, witness.Snapshot, replay.Snapshot, raw); err != nil {
		t.Fatal(err)
	}
	for i := range witness.Blocks {
		block := executionwitness.BlockTransition{Index: strconv.Itoa(i), Genesis: i == 0}
		raw, _ := json.Marshal(block)
		if _, err := s.pool.Exec(ctx, `INSERT INTO governance_transition_blocks VALUES($1,$2,$3::numeric,$4)`, gov.ID, witness.Snapshot, block.Index, raw); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ = json.Marshal(executionwitness.TransactionTransition{Index: "25", Hash: op.TxHash, BlockHash: *op.BlockHash})
	if _, err := s.pool.Exec(ctx, `INSERT INTO governance_transition_transactions VALUES($1,$2,25,0,$3)`, gov.ID, witness.Snapshot, raw); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		report, err := storedEpochTransitionReport(ctx, tx, witness, replay)
		if err == nil && (len(report.Blocks) != 26 || len(report.Transactions) != 1 || len(report.Execution.Source.Blocks) != 26 || report.Transactions[0].Hash != op.TxHash) {
			t.Fatal("incomplete reconstructed rows")
		}
		return err
	}); err != nil {
		t.Fatal("complete owned rows refused", err)
	}
	for _, test := range []struct {
		name, sql string
	}{
		{"missing transition block", `DELETE FROM governance_transition_blocks WHERE dataset_id=$1 AND index_=25`},
		{"missing execution block", `DELETE FROM governance_execution_blocks WHERE dataset_id=$1 AND index_=25`},
		{"extra transition block", `INSERT INTO governance_transition_blocks SELECT dataset_id,snapshot,26,block FROM governance_transition_blocks WHERE dataset_id=$1 AND index_=25`},
		{"block JSON index mismatch", `UPDATE governance_transition_blocks SET block=jsonb_set(block,'{index}','"24"') WHERE dataset_id=$1 AND index_=25`},
		{"broken parent link", `UPDATE governance_execution_blocks SET block=jsonb_set(block,'{parent_hash}','"different"') WHERE dataset_id=$1 AND index_=25`},
		{"missing transition transaction", `DELETE FROM governance_transition_transactions WHERE dataset_id=$1`},
		{"missing execution transaction", `DELETE FROM governance_execution_transactions WHERE dataset_id=$1`},
		{"transaction hash mismatch", `UPDATE governance_transition_transactions SET point=jsonb_set(point,'{hash}','"different"') WHERE dataset_id=$1`},
		{"transaction ordinal gap", `UPDATE governance_transition_transactions SET tx_ordinal=1,point=jsonb_set(point,'{transaction_index}','1') WHERE dataset_id=$1`},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := s.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
					t.Error(rollbackErr)
				}
			}()
			if _, err = tx.Exec(ctx, test.sql, gov.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = storedEpochTransitionReport(ctx, tx, witness, replay); !errors.Is(err, ErrGovernanceTransitionBinding) {
				t.Fatal("inconsistent stored rows were accepted", err)
			}
		})
	}
	for _, name := range []string{"wrong owner", "wrong execution snapshot", "wrong count", "over bound", "wrong verifier", "unsupported protocol"} {
		t.Run(name, func(t *testing.T) {
			w, r := witness, replay
			switch name {
			case "wrong owner":
				w.DatasetID++
			case "wrong execution snapshot":
				w.ExecutionSnapshot = strings.Repeat("a", 64)
			case "wrong count":
				w.Transactions++
			case "over bound":
				w.Blocks, r.Blocks = executionwitness.MaxBlocks+1, executionwitness.MaxBlocks+1
			case "wrong verifier":
				w.Source.Verifier.SHA256 = strings.Repeat("a", 64)
			case "unsupported protocol":
				w.Source.Report.Execution.Protocol, r.Source.Report.Protocol = "unknown", "unknown"
			}
			if err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
				_, err := storedEpochTransitionReport(ctx, tx, w, r)
				return err
			}); !errors.Is(err, ErrGovernanceTransitionBinding) {
				t.Fatal("mismatched parent metadata was accepted", err)
			}
		})
	}
}
