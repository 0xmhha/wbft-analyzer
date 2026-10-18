package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/statewitness"
	"github.com/jackc/pgx/v5"
)

func TestTransitionSummaryRequiresAllSourcesAndPreservesConflicts(t *testing.T) {
	entry := GovernanceTransitionEvidence{Binding: "matched", Status: "matched", CauseStatus: "verified_transaction_effect", Point: &executionwitness.TransactionTransition{CauseStatus: "verified_transaction_effect"}, NextEpoch: &executionwitness.BlockTransition{Index: "100"}}
	for _, test := range []struct {
		name, status, cause string
		alter               func(*GovernanceTransitionEvidenceList)
	}{
		{"all matched", "matched", "verified_transaction_effect", func(*GovernanceTransitionEvidenceList) {}},
		{"truncated", "ambiguous", "ambiguous", func(v *GovernanceTransitionEvidenceList) { v.Truncated = true }},
		{"different next epoch coverage", "matched", "verified_transaction_effect", func(v *GovernanceTransitionEvidenceList) { v.Evidence[1].NextEpoch = nil }},
		{"missing source", "unverified", "unestablished", func(v *GovernanceTransitionEvidenceList) {
			v.Evidence[1].Binding = "source_unavailable"
			v.Evidence[1].NextEpoch = nil
		}},
		{"unknown effect", "matched", "unestablished", func(v *GovernanceTransitionEvidenceList) { v.Evidence[1].CauseStatus = "unestablished" }},
		{"conflicting state", "ambiguous", "ambiguous", func(v *GovernanceTransitionEvidenceList) {
			p := *v.Evidence[1].Point
			p.Method = "different"
			v.Evidence[1].Point = &p
		}},
		{"reported mismatch", "mismatch", "unestablished", func(v *GovernanceTransitionEvidenceList) {
			v.Evidence[0].Status = "mismatch"
			v.Evidence[1].Status = "mismatch"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := GovernanceTransitionEvidenceList{Evidence: []GovernanceTransitionEvidence{entry, entry}}
			test.alter(&value)
			summarizeTransitionEvidence(&value)
			if value.Status != test.status || value.CauseStatus != test.cause {
				t.Fatalf("registry summary depends on independent epoch context: got %s/%s, want %s/%s", value.Status, value.CauseStatus, test.status, test.cause)
			}
		})
	}
}

func TestTransitionOpaqueAtomicAdmissionAndExport(t *testing.T) {
	binary, dir := os.Getenv("WBFT_EXECUTION_TEST_HELPER"), os.Getenv("WBFT_EXECUTION_TEST_SOURCE")
	if binary == "" || dir == "" {
		t.Skip("synthetic helper integration inputs are not configured")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(executable)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	bundle, err := executionwitness.LoadTransitions(context.Background(), raw, root, executionwitness.Helper{Path: binary, SHA256: hex.EncodeToString(sum[:]), Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	source := bundle.Projection().Report.Execution.Source
	gov := witnessGovernanceDataset(t, s, statewitness.Snapshot{Node: source.Node, ChainID: source.ChainID, GenesisHash: source.GenesisHash}, "opaque-transitions", source.Node)
	if _, err = s.PutGovernanceTransitions(ctx, gov.ID, gov.ID, executionwitness.TransitionBundle{}); !errors.Is(err, ErrGovernanceTransitionBinding) {
		t.Fatal("zero transition bundle admitted", err)
	}
	var capture GovernanceCapture
	if err = s.pool.QueryRow(ctx, `SELECT info FROM governance_captures WHERE dataset_id=$1`, gov.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &capture) != nil {
		t.Fatal("capture")
	}
	capture.To = "0x0"
	raw, _ = json.Marshal(capture)
	if _, err = s.pool.Exec(ctx, `UPDATE governance_captures SET info=$2 WHERE dataset_id=$1`, gov.ID, raw); err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(map[string]string{"config_sha256": source.ConfigSHA256})
	head, release, err := s.BeginRange(ctx, NetworkKey{ChainID: source.ChainID, GenesisHash: source.GenesisHash}, "transition-headers", meta)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, head.ID, 0, ""); err != nil {
		t.Fatal(err)
	}
	release()
	var first GovernanceTransitionWitness
	for range 2 {
		got, err := s.PutGovernanceTransitions(ctx, gov.ID, head.ID, bundle)
		if err != nil {
			t.Fatal(err)
		}
		if first.Snapshot != "" && first.Snapshot != got.Snapshot {
			t.Fatal("snapshot changed")
		}
		first = got
	}
	if first.Blocks != 1 || first.Transactions != 0 || len(first.Source.Report.Blocks) != 0 || len(first.Source.Report.Execution.Source.Blocks) != 0 {
		t.Fatal("parent metadata is unbounded")
	}
	bad, release, err := s.BeginRange(ctx, NetworkKey{ChainID: source.ChainID, GenesisHash: source.GenesisHash}, "wrong-transition-config", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, bad.ID, 0, ""); err != nil {
		t.Fatal(err)
	}
	release()
	if _, err = s.PutGovernanceTransitions(ctx, gov.ID, bad.ID, bundle); !errors.Is(err, ErrExecutionWitnessBinding) {
		t.Fatal("wrong configuration admitted", err)
	}
	var original []byte
	if err = s.pool.QueryRow(ctx, `SELECT block FROM governance_transition_blocks WHERE dataset_id=$1`, gov.ID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, `UPDATE governance_transition_blocks SET block='{}' WHERE dataset_id=$1`, gov.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PutGovernanceTransitions(ctx, gov.ID, head.ID, bundle); !errors.Is(err, ErrGovernanceTransitionBinding) {
		t.Fatal("immutable transition overwritten", err)
	}
	if _, err = s.pool.Exec(ctx, `UPDATE governance_transition_blocks SET block=$2 WHERE dataset_id=$1`, gov.ID, original); err != nil {
		t.Fatal(err)
	}
	if err = s.pool.QueryRow(ctx, `SELECT block FROM governance_execution_blocks WHERE dataset_id=$1`, gov.ID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, `UPDATE governance_execution_blocks SET block=jsonb_set(block,'{state_root}','"changed"') WHERE dataset_id=$1`, gov.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PutGovernanceTransitions(ctx, gov.ID, head.ID, bundle); !errors.Is(err, ErrExecutionWitnessBinding) {
		t.Fatal("immutable replay overwritten", err)
	}
	if _, err = s.pool.Exec(ctx, `UPDATE governance_execution_blocks SET block=$2 WHERE dataset_id=$1`, gov.ID, original); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"governance_execution_witnesses", "governance_execution_blocks", "governance_transition_witnesses", "governance_transition_blocks"} {
		var count int
		if err = s.pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE dataset_id=$1`, gov.ID).Scan(&count); err != nil || count != 1 {
			t.Fatal("refused attachment leaked a prefix", table, count, err)
		}
	}
	out := filepath.Join(t.TempDir(), "transition-export")
	manifest, err := s.ExportDataset(ctx, gov.Name, out, "public")
	if err != nil {
		t.Fatal(err)
	}
	assertBundleDigests(t, out, manifest)
	if len(manifest.Datasets) != 2 {
		t.Fatal("canonical dependency omitted")
	}
	for _, table := range []string{"governance_transition_witnesses", "governance_transition_blocks"} {
		if len(exportRows(t, out, table)) != 1 {
			t.Fatal("transition export omitted", table)
		}
	}
	if _, err = s.DeleteDataset(ctx, gov.NetworkID, gov.ID, gov.Name); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"governance_execution_witnesses", "governance_transition_witnesses", "governance_transition_blocks", "governance_transition_transactions"} {
		var count int
		if err = s.pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE dataset_id=$1`, gov.ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("transition owner survived deletion", table, count, err)
		}
	}
}

// Persisted synthetic rows test query ownership and invalidation independently
// of replay admission. They never construct a verified bundle or claim a VM ran.
func TestTransitionQueryBindsOriginalHeaderDependency(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	gov, head, replay, op := executionStoredFixture(t, s)
	point := executionwitness.TransactionTransition{Index: "25", Ordinal: 0, Hash: op.TxHash, BlockHash: *op.BlockHash, CauseStatus: "unestablished", Reason: "reverted_transaction"}
	w := GovernanceTransitionWitness{DatasetID: gov.ID, Snapshot: strings.Repeat("d", 64), ExecutionSnapshot: replay.Snapshot, Source: executionwitness.TransitionProjection{Report: executionwitness.TransitionReport{Protocol: executionwitness.TransitionProtocol, Execution: replay.Source.Report}, Verifier: replay.Source.Verifier}, Blocks: 26, Transactions: 1}
	raw, _ := json.Marshal(w)
	if _, err := s.pool.Exec(ctx, `INSERT INTO governance_transition_witnesses VALUES($1,$2,$3,$4)`, gov.ID, w.Snapshot, replay.Snapshot, raw); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(executionwitness.BlockTransition{Index: "25"})
	if _, err := s.pool.Exec(ctx, `INSERT INTO governance_transition_blocks VALUES($1,$2,25,$3)`, gov.ID, w.Snapshot, raw); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(point)
	if _, err := s.pool.Exec(ctx, `INSERT INTO governance_transition_transactions VALUES($1,$2,25,0,$3)`, gov.ID, w.Snapshot, raw); err != nil {
		t.Fatal(err)
	}
	read := func(op *governance.Operation) GovernanceTransitionEvidenceList {
		t.Helper()
		var value GovernanceTransitionEvidenceList
		err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
			var err error
			value, err = governanceTransitionEvidence(ctx, tx, gov.NetworkID, gov.ID, "25", op)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if got := read(&op); got.Status != "matched" || got.CauseStatus != "unestablished" || len(got.Evidence) != 1 {
		t.Fatal("reverted operation became causal", got)
	}
	if got := read(nil); got.Status != "matched" || got.Evidence[0].Reason != "header_state_only" || got.Evidence[0].Point != nil {
		t.Fatal("epoch state invented a transaction", got)
	}
	copy := op
	copy.Path = []uint32{0}
	if got := read(&copy); got.Status != "unverified" || got.CauseStatus != "unestablished" {
		t.Fatal("nested path inferred", got)
	}
	var execution executionwitness.Transaction
	if err := s.pool.QueryRow(ctx, `SELECT point FROM governance_execution_transactions WHERE dataset_id=$1`, gov.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &execution) != nil {
		t.Fatal("execution fixture")
	}
	execution.ReceiptStatus = "succeeded"
	execution.Frames[0].Status = "succeeded"
	execution.Frames[0].Effective = true
	execution.Frames[0].ABIStatus = "not_reverted"
	execution.Frames[0].ErrorName = ""
	raw, _ = json.Marshal(execution)
	if _, err := s.pool.Exec(ctx, `UPDATE governance_execution_transactions SET point=$2 WHERE dataset_id=$1`, gov.ID, raw); err != nil {
		t.Fatal(err)
	}
	point.CauseStatus = "verified_transaction_effect"
	point.Reason = "reviewed_runtime_writes"
	raw, _ = json.Marshal(point)
	if _, err := s.pool.Exec(ctx, `UPDATE governance_transition_transactions SET point=$2 WHERE dataset_id=$1`, gov.ID, raw); err != nil {
		t.Fatal(err)
	}
	op.Effective = true
	op.Result = "success"
	op.ErrorName = ""
	op.ResultValue = sourceText("success")
	if got := read(&op); got.Status != "matched" || got.CauseStatus != "verified_transaction_effect" {
		t.Fatal("bound operation did not retain verified fixture cause", got)
	}
	copy = op
	copy.TxHash = "different"
	if got := read(&copy); got.Status != "mismatch" || got.CauseStatus != "unestablished" {
		t.Fatal("different source transaction borrowed a cause", got)
	}
	copy = op
	copy.Path = []uint32{0}
	if got := read(&copy); got.Status != "unverified" || got.CauseStatus != "unestablished" {
		t.Fatal("nested source path borrowed root cause", got)
	}
	meta, _ := json.Marshal(map[string]string{"config_sha256": replay.Source.Report.Source.ConfigSHA256})
	alternate, release, err := s.BeginRange(ctx, NetworkKey{ChainID: "7", GenesisHash: replay.Source.Report.Source.GenesisHash}, "alternate-transition-headers", meta)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.pool.Query(ctx, `SELECT fact FROM heights WHERE network_id=$1 ORDER BY index_`, gov.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (headers.Fact, error) {
		var raw []byte
		if err := row.Scan(&raw); err != nil {
			return headers.Fact{}, err
		}
		var fact headers.Fact
		err := json.Unmarshal(raw, &fact)
		return fact, err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fact := range facts {
		if err = s.PutHeaders(ctx, alternate.ID, alternate.NetworkID, []headers.Fact{fact}, []headers.Copy{{Index: fact.Index, Hash: fact.Hash, Node: "alternate-synthetic-node"}}, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.FinishRange(ctx, alternate.ID, int64(len(facts)), ""); err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := s.DeleteDataset(ctx, head.NetworkID, head.ID, head.Name); err != nil {
		t.Fatal(err)
	}
	if got := read(&op); got.Status != "unverified" || got.CauseStatus != "unestablished" || got.Evidence[0].Binding != "source_unavailable" || got.Evidence[0].Replay.HeadersDataset != nil || got.Evidence[0].Replay.HeaderSourceID != head.ID {
		t.Fatal("deleted dependency remained bound", got)
	}
}
