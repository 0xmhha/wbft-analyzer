package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/privacy"
	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/statewitness"
	"github.com/jackc/pgx/v5"
)

func executionComparisonFixture() (GovernanceExecutionEvidence, governance.Operation) {
	hash := "0x" + strings.Repeat("a", 64)
	point := executionwitness.Transaction{Index: "25", Ordinal: 0, Hash: "0x" + strings.Repeat("b", 64), BlockHash: hash, From: "0x" + strings.Repeat("1", 40), To: "0x" + strings.Repeat("2", 40), Input: executionwitness.Digest{SHA256: strings.Repeat("c", 64), Bytes: 4}, Selector: "0x11223344", ReceiptStatus: "failed", Logs: []executionwitness.Log{}, Frames: []executionwitness.Frame{{Path: []uint32{}, Status: "reverted", ABIStatus: "decoded_revert", ErrorName: "InvalidProposal", Return: executionwitness.Digest{SHA256: strings.Repeat("d", 64), Bytes: 4}}}}
	op := governance.Operation{BlockHash: &hash, Number: "0x19", Tx: 0, TxHash: point.Hash, Path: []uint32{}, From: point.From, Instance: point.To, Input: governance.Bytes{SHA256: point.Input.SHA256, Length: point.Input.Bytes}, Selector: point.Selector, Result: "revert", ErrorName: "InvalidProposal", ResultValue: sourceText("InvalidProposal"), Logs: []governance.Log{}}
	return GovernanceExecutionEvidence{Point: point, Binding: "matched"}, op
}
func TestExecutionOperationComparisonPreservesUnknownAndMismatch(t *testing.T) {
	valid, op := executionComparisonFixture()
	compareExecutionOperation(&valid, op)
	if valid.Status != "matched" || valid.ErrorStatus != "matched" {
		t.Fatal(valid)
	}
	for _, test := range []struct {
		name, status, reason string
		change               func(*governance.Operation)
	}{
		{"missing hash", "unverified", "source_hash_unavailable", func(o *governance.Operation) { o.BlockHash = nil }},
		{"nested path", "unverified", "nested_path_unmapped", func(o *governance.Operation) { o.Path = []uint32{0} }},
		{"wrong transaction", "mismatch", "identity_mismatch", func(o *governance.Operation) { o.Tx = 1 }},
		{"wrong height", "mismatch", "identity_mismatch", func(o *governance.Operation) { o.Number = "0x10000000000000019" }},
		{"wrong call", "mismatch", "identity_mismatch", func(o *governance.Operation) { o.Input.Length++ }},
		{"wrong error", "mismatch", "outcome_mismatch", func(o *governance.Operation) { o.ErrorName = "NotAMember"; o.ResultValue = sourceText("NotAMember") }},
		{"claimed effect", "mismatch", "outcome_mismatch", func(o *governance.Operation) { o.Effective = true }},
		{"view claim", "mismatch", "outcome_mismatch", func(o *governance.Operation) { o.View = true }},
		{"extra log", "mismatch", "logs_mismatch", func(o *governance.Operation) { o.Logs = []governance.Log{{}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry, copy := executionComparisonFixture()
			test.change(&copy)
			compareExecutionOperation(&entry, copy)
			if entry.Status != test.status || entry.Reason != test.reason {
				t.Fatal(entry)
			}
		})
	}
	entry, op := executionComparisonFixture()
	entry.Binding = "source_unavailable"
	compareExecutionOperation(&entry, op)
	if entry.Status != "unverified" {
		t.Fatal("missing canonical source became verified")
	}
	entry, op = executionComparisonFixture()
	entry.Point.Frames[0].ABIStatus = "unknown_runtime"
	entry.Point.Frames[0].ErrorName = ""
	compareExecutionOperation(&entry, op)
	if entry.ErrorStatus != "unverified" || entry.Status != "unverified" {
		t.Fatal("source error was used to name unknown runtime")
	}
	entry, op = executionComparisonFixture()
	op.ErrorName = ""
	op.ResultValue = sourceText("revert")
	compareExecutionOperation(&entry, op)
	if entry.Status != "matched" || entry.ErrorStatus != "not_reported" {
		t.Fatal("generic source revert conflated with a named error", entry)
	}
	entry, op = executionComparisonFixture()
	entry.Point.Frames[0].ErrorName = "DuplicateMember"
	op.Result = "unknown"
	op.ErrorName = ""
	op.ResultValue = sourceText("DuplicateMember")
	compareExecutionOperation(&entry, op)
	if entry.ErrorStatus != "matched" {
		t.Fatal("retained exact source digest not compared independently")
	}
}
func TestExecutionWitnessesCannotSelectLatestMatchingSource(t *testing.T) {
	a, op := executionComparisonFixture()
	compareExecutionOperation(&a, op)
	for _, test := range []struct {
		name, status string
		alter        func(*GovernanceExecutionEvidenceList)
	}{
		{"matching", "matched", func(*GovernanceExecutionEvidenceList) {}},
		{"truncated", "ambiguous", func(v *GovernanceExecutionEvidenceList) { v.Truncated = true }},
		{"missing dependency", "unverified", func(v *GovernanceExecutionEvidenceList) { v.Evidence[1].Binding = "source_unavailable" }},
		{"conflicting result", "ambiguous", func(v *GovernanceExecutionEvidenceList) { v.Evidence[1].Point.ReceiptStatus = "succeeded" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := GovernanceExecutionEvidenceList{Evidence: []GovernanceExecutionEvidence{a, a}}
			test.alter(&v)
			summarizeExecutionEvidence(&v)
			if v.Status != test.status {
				t.Fatal(v)
			}
		})
	}
}

// This fixture models persisted synthetic rows for query/ownership tests. It
// never constructs an opaque loader bundle or claims that its VM ran.
func executionStoredFixture(t *testing.T, s *Store) (Dataset, Dataset, GovernanceExecutionWitness, governance.Operation) {
	t.Helper()
	ctx := context.Background()
	node := "0x" + strings.Repeat("1", 40)
	genesis := fmt.Sprintf("0x%064x", 1)
	state := statewitness.Snapshot{Node: node, ChainID: "7", GenesisHash: genesis}
	gov := witnessGovernanceDataset(t, s, state, "execution-governance", node)
	meta := []byte(`{"config_sha256":"` + strings.Repeat("c", 64) + `"}`)
	head, release, err := s.BeginRange(ctx, NetworkKey{ChainID: "7", GenesisHash: genesis}, "execution-headers", meta)
	if err != nil {
		t.Fatal(err)
	}
	entry, op := executionComparisonFixture()
	source := executionwitness.Snapshot{Format: executionwitness.InputFormat, Node: node, ChainID: "7", GenesisHash: genesis, ConfigSHA256: strings.Repeat("c", 64), Blocks: []executionwitness.BlockEvidence{}}
	witness := GovernanceExecutionWitness{DatasetID: gov.ID, Snapshot: strings.Repeat("e", 64), HeadersDataset: &head.ID, HeaderSourceID: head.ID, Source: executionwitness.Projection{Report: executionwitness.Report{Protocol: executionwitness.Protocol, Origin: executionwitness.Origin{Path: executionwitness.OriginPath, Version: executionwitness.OriginVersion, Sum: executionwitness.OriginSum}, Source: source, Transactions: []executionwitness.Transaction{}}, Verifier: executionwitness.Verifier{SHA256: strings.Repeat("f", 64)}}, Blocks: 26, Transactions: 1}
	info, _ := json.Marshal(witness)
	if _, err = s.pool.Exec(ctx, `INSERT INTO governance_execution_witnesses VALUES($1,$2,$3,$3,$4)`, gov.ID, witness.Snapshot, head.ID, info); err != nil {
		t.Fatal(err)
	}
	previous := "0x" + strings.Repeat("0", 64)
	for n := 0; n <= 25; n++ {
		hash := fmt.Sprintf("0x%064x", n+1)
		if n == 25 {
			hash = op.TxHash
			op.BlockHash = &hash
			entry.Point.BlockHash = hash
		}
		block := executionwitness.BlockEvidence{Index: fmt.Sprint(n), Hash: hash, Parent: previous}
		raw, _ := json.Marshal(block)
		if _, err = s.pool.Exec(ctx, `INSERT INTO governance_execution_blocks VALUES($1,$2,$3::numeric,$4)`, gov.ID, witness.Snapshot, block.Index, raw); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			fact := headers.Fact{Index: block.Index, Number: block.Index, Hash: hash, ParentHash: previous}
			copy := headers.Copy{Index: block.Index, Hash: hash, Node: "synthetic-header-node"}
			if err = s.PutHeaders(ctx, head.ID, head.NetworkID, []headers.Fact{fact}, []headers.Copy{copy}, 1); err != nil {
				t.Fatal(err)
			}
		}
		previous = hash
	}
	if err = s.FinishRange(ctx, head.ID, 25, ""); err != nil {
		t.Fatal(err)
	}
	release()
	point, _ := json.Marshal(entry.Point)
	if _, err = s.pool.Exec(ctx, `INSERT INTO governance_execution_transactions VALUES($1,$2,25,0,$3)`, gov.ID, witness.Snapshot, point); err != nil {
		t.Fatal(err)
	}
	var capture GovernanceCapture
	var raw []byte
	if err = s.pool.QueryRow(ctx, `SELECT info FROM governance_captures WHERE dataset_id=$1`, gov.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &capture) != nil {
		t.Fatal("capture fixture")
	}
	capture.Calls = []GovernanceCall{{Ordinal: 1, Request: governance.Request{Method: "wbft_govOps"}, Status: "available"}}
	raw, _ = json.Marshal(capture)
	if _, err = s.pool.Exec(ctx, `UPDATE governance_captures SET info=$2 WHERE dataset_id=$1`, gov.ID, raw); err != nil {
		t.Fatal(err)
	}
	call, _ := json.Marshal(governance.Call{Ordinal: 1, Request: governance.Request{Method: "wbft_govOps"}, Status: "available", Data: json.RawMessage(`[]`)})
	if _, err = s.pool.Exec(ctx, `INSERT INTO governance_calls(dataset_id,ordinal,method,call) VALUES($1,1,'wbft_govOps',$2)`, gov.ID, call); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(op)
	if _, err = s.pool.Exec(ctx, `INSERT INTO gov_ops(dataset_id,call_ordinal,ordinal,source_path,number,instance,tx_index,row_) VALUES($1,1,1,'0',25,$2,0,$3)`, gov.ID, op.Instance, raw); err != nil {
		t.Fatal(err)
	}
	return gov, head, witness, op
}
func TestGovernanceExecutionCanonicalScopeExportAndDeletion(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	gov, head, w, op := executionStoredFixture(t, s)
	if _, err := s.PutGovernanceExecutionWitness(ctx, gov.ID, head.ID, executionwitness.Bundle{}); !errors.Is(err, ErrExecutionWitnessBinding) {
		t.Fatal("zero bundle accepted", err)
	}
	read := func() GovernanceExecutionEvidenceList {
		t.Helper()
		value, err := s.GovernanceHeaderContext(ctx, gov.ID, 1, 1, "operations")
		if err != nil || value.Execution == nil {
			t.Fatal(value, err)
		}
		if value.CauseStatus != "unestablished" {
			t.Fatal("cause inferred")
		}
		return *value.Execution
	}
	if got := read(); got.Status != "matched" || got.ErrorStatus != "matched" {
		t.Fatal(got)
	}
	for _, test := range []struct{ name, query, status, restore string }{
		{"prefix header", "UPDATE heights SET fact=jsonb_set(fact,'{number}','\"18446744073709551617\"') WHERE network_id=$1 AND index_=1", "header_mismatch", "UPDATE heights SET fact=jsonb_set(fact,'{number}','\"1\"') WHERE network_id=$1 AND index_=1"},
		{"prefix copy", "UPDATE header_copies SET copy=jsonb_set(copy,'{hash}','\"invalid\"') WHERE dataset_id=$1 AND index_=1", "header_unavailable", "UPDATE header_copies SET copy=jsonb_set(copy,'{hash}',to_jsonb(hash)) WHERE dataset_id=$1 AND index_=1"},
		{"network identity", "UPDATE networks SET chain_id='8' WHERE id=$1", "network_mismatch", "UPDATE networks SET chain_id='7' WHERE id=$1"},
		{"configuration", "UPDATE datasets SET metadata='{}' WHERE id=$1", "config_mismatch", "UPDATE datasets SET metadata=jsonb_build_object('config_sha256',repeat('c',64)) WHERE id=$1"},
		{"source status", "UPDATE datasets SET status='failed' WHERE id=$1", "source_unavailable", "UPDATE datasets SET status='complete' WHERE id=$1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := head.ID
			if test.name == "prefix header" || test.name == "network identity" {
				id = head.NetworkID
			}
			if _, err := s.pool.Exec(ctx, test.query, id); err != nil {
				t.Fatal(err)
			}
			got := read()
			if got.Status != "unverified" || len(got.Evidence) != 1 || got.Evidence[0].Binding != test.status {
				t.Fatal(got)
			}
			if _, err := s.pool.Exec(ctx, test.restore, id); err != nil {
				t.Fatal(err)
			}
		})
	}
	other := witnessGovernanceDataset(t, s, statewitness.Snapshot{Node: op.From, ChainID: "7", GenesisHash: w.Source.Report.Source.GenesisHash}, "other-execution-governance", op.From)
	if err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		otherRows, err := governanceExecutionEvidence(ctx, tx, gov.NetworkID, other.ID, "25", op)
		if err != nil {
			return err
		}
		if len(otherRows.Evidence) != 0 {
			t.Fatal("cross-dataset evidence")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "execution-export")
	m, err := s.ExportDataset(ctx, gov.Name, out, "public")
	if err != nil {
		t.Fatal(err)
	}
	assertBundleDigests(t, out, m)
	if len(m.Datasets) != 2 {
		t.Fatal("canonical dependency missing", m.Datasets)
	}
	for name, want := range map[string]int{"governance_execution_witnesses": 1, "governance_execution_blocks": 26, "governance_execution_transactions": 1} {
		if rows := exportRows(t, out, name); len(rows) != want {
			t.Fatal(name, len(rows))
		}
	}
	if privacy.Visibility() == "public" {
		if _, err = s.pool.Exec(ctx, `UPDATE datasets SET visibility='private' WHERE id=$1`, gov.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = s.GovernanceHeaderContext(ctx, gov.ID, 1, 1, "operations"); !errors.Is(err, ErrNotFound) {
			t.Fatal("private owner exposed", err)
		}
		if _, err = s.pool.Exec(ctx, `UPDATE datasets SET visibility='public' WHERE id=$1`, gov.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = s.pool.Exec(ctx, `UPDATE datasets SET visibility='private' WHERE id=$1`, head.ID); err != nil {
			t.Fatal(err)
		}
		if got := read(); got.Status != "unverified" || got.Evidence[0].Binding != "network_mismatch" {
			t.Fatal(got)
		}
		if _, err = s.ExportDataset(ctx, gov.Name, filepath.Join(t.TempDir(), "refused"), "public"); !errors.Is(err, ErrExportPrivate) {
			t.Fatal("private dependency exported", err)
		}
		if _, err = s.pool.Exec(ctx, `UPDATE datasets SET visibility='public' WHERE id=$1`, head.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.DeleteDataset(ctx, head.NetworkID, head.ID, head.Name); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.Status != "unverified" || got.Evidence[0].Witness.HeadersDataset != nil || got.Evidence[0].Witness.HeaderSourceID != head.ID {
		t.Fatal("deleted source remained matched", got)
	}
	out = filepath.Join(t.TempDir(), "without-header")
	m, err = s.ExportDataset(ctx, gov.Name, out, "public")
	if err != nil || len(m.Datasets) != 1 {
		t.Fatal(m, err)
	}
	if _, err = s.DeleteDataset(ctx, gov.NetworkID, gov.ID, gov.Name); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"governance_execution_witnesses", "governance_execution_blocks", "governance_execution_transactions"} {
		var n int
		if err = s.pool.QueryRow(ctx, `SELECT count(*) FROM `+name).Scan(&n); err != nil || n != 0 {
			t.Fatal(name, n, err)
		}
	}
}

func TestGovernanceExecutionOpaqueAdmissionAndIdempotence(t *testing.T) {
	binary, dir := os.Getenv("WBFT_EXECUTION_TEST_HELPER"), os.Getenv("WBFT_EXECUTION_TEST_SOURCE")
	if binary == "" || dir == "" {
		t.Skip("synthetic helper integration inputs are not configured")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, executable)
	closeErr := executable.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal(copyErr, closeErr)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	bundle, err := executionwitness.Load(context.Background(), raw, root, executionwitness.Helper{Path: binary, SHA256: hex.EncodeToString(h.Sum(nil)), Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	source := bundle.Projection().Report.Source
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	gov := witnessGovernanceDataset(t, s, statewitness.Snapshot{Node: source.Node, ChainID: source.ChainID, GenesisHash: source.GenesisHash}, "opaque-execution", source.Node)
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
	head, release, err := s.BeginRange(ctx, NetworkKey{ChainID: source.ChainID, GenesisHash: source.GenesisHash}, "opaque-headers", meta)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, head.ID, 0, ""); err != nil {
		t.Fatal(err)
	}
	release()
	var first GovernanceExecutionWitness
	for range 2 {
		got, err := s.PutGovernanceExecutionWitness(ctx, gov.ID, head.ID, bundle)
		if err != nil {
			t.Fatal(err)
		}
		if first.Snapshot != "" && first.Snapshot != got.Snapshot {
			t.Fatal("idempotent snapshot changed")
		}
		first = got
	}
	if first.Blocks != 1 || first.Transactions != 0 || len(first.Source.Report.Source.Blocks) != 0 || len(first.Source.Report.Transactions) != 0 {
		t.Fatal("unbounded parent metadata", first)
	}
	bad, release, err := s.BeginRange(ctx, NetworkKey{ChainID: source.ChainID, GenesisHash: source.GenesisHash}, "unbound-headers", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, bad.ID, 0, ""); err != nil {
		t.Fatal(err)
	}
	release()
	if _, err = s.PutGovernanceExecutionWitness(ctx, gov.ID, bad.ID, bundle); !errors.Is(err, ErrExecutionWitnessBinding) {
		t.Fatal("mismatched configuration accepted", err)
	}
	var parents, blocks int
	if err = s.pool.QueryRow(ctx, `SELECT count(*) FROM governance_execution_witnesses WHERE dataset_id=$1`, gov.ID).Scan(&parents); err != nil {
		t.Fatal(err)
	}
	if err = s.pool.QueryRow(ctx, `SELECT count(*) FROM governance_execution_blocks WHERE dataset_id=$1`, gov.ID).Scan(&blocks); err != nil {
		t.Fatal(err)
	}
	if parents != 1 || blocks != 1 {
		t.Fatal("duplicate or refused attachment persisted", parents, blocks)
	}
}

func TestExecutionFullHistoryScopeBoundary(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	gov, _, _, op := executionStoredFixture(t, s)
	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT info FROM governance_captures WHERE dataset_id=$1`, gov.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var capture GovernanceCapture
	if json.Unmarshal(raw, &capture) != nil {
		t.Fatal("capture")
	}
	capture.To = "0x18"
	capture.Calls[0].Request = governance.Request{Method: "wbft_govProposal", Scope: "proposal-full-history-current-state"}
	raw, _ = json.Marshal(capture)
	if _, err := s.pool.Exec(ctx, `UPDATE governance_captures SET info=$2 WHERE dataset_id=$1`, gov.ID, raw); err != nil {
		t.Fatal(err)
	}
	value, err := s.GovernanceHeaderContext(ctx, gov.ID, 1, 1, "operations")
	if err != nil || value.Execution == nil || value.Execution.Status != "matched" {
		t.Fatalf("independent proposal history incorrectly bounded by govOps interval: %v %v", value.Execution, err)
	}
	op.Tx = 1
	raw, _ = json.Marshal(op)
	if _, err = s.pool.Exec(ctx, `UPDATE gov_ops SET tx_index=1,row_=$2 WHERE dataset_id=$1 AND call_ordinal=1 AND ordinal=1`, gov.ID, raw); err != nil {
		t.Fatal(err)
	}
	value, err = s.GovernanceHeaderContext(ctx, gov.ID, 1, 1, "operations")
	if err != nil || value.Execution == nil || value.Execution.Status != "unverified" || len(value.Execution.Evidence) != 0 {
		t.Fatal("missing replay point inferred from a neighboring transaction", value.Execution, err)
	}

}
