package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/privacy"
	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/statewitness"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
	"github.com/jackc/pgx/v5"
)

type epochRegistryFixture struct {
	gov, head Dataset
	witness   GovernanceTransitionWitness
	replay    GovernanceExecutionWitness
	report    executionwitness.TransitionReport
}

func epochFixtureDigest(value []byte) executionwitness.Digest {
	sum := sha256.Sum256(value)
	return executionwitness.Digest{SHA256: hex.EncodeToString(sum[:]), Bytes: len(value)}
}

// These are persisted synthetic records for read, pagination and ownership
// tests. They never construct an opaque bundle or claim a VM execution occurred.
func newEpochRegistryFixture(t *testing.T, s *Store) epochRegistryFixture {
	t.Helper()
	ctx := context.Background()
	address, member := "0x"+strings.Repeat("1", 40), "0x"+strings.Repeat("2", 40)
	code := "0xb5ce66a9f8c1a08247521c60191f8b11e31e472d8dc26ea163e66de307303dac"
	genesis, blockHash, epochHash, txHash := fmt.Sprintf("0x%064x", 1), fmt.Sprintf("0x%064x", 2), fmt.Sprintf("0x%064x", 3), fmt.Sprintf("0x%064x", 4)
	gov := witnessGovernanceDataset(t, s, statewitness.Snapshot{Node: member, ChainID: "7", GenesisHash: genesis}, "epoch-registry-source", member)
	meta := []byte(`{"config_sha256":"` + strings.Repeat("c", 64) + `"}`)
	head, release, err := s.BeginRange(ctx, NetworkKey{ChainID: "7", GenesisHash: genesis}, "epoch-registry-headers", meta)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte(strings.Repeat("k", 48))
	var candidateAddress types.Address
	for i := range candidateAddress {
		candidateAddress[i] = 0x22
	}
	info, _ := json.Marshal(types.EpochInfo{Candidates: []types.Candidate{{Addr: candidateAddress}}, Validators: []uint32{0}, BLSPublicKeys: [][]byte{key}})
	facts := []headers.Fact{{Index: "1", Number: "1", Hash: blockHash, ParentHash: genesis}, {Index: "2", Number: "2", Hash: epochHash, ParentHash: blockHash, EpochInfo: info}}
	for _, fact := range facts {
		if err = s.PutHeaders(ctx, head.ID, head.NetworkID, []headers.Fact{fact}, []headers.Copy{{Index: fact.Index, Hash: fact.Hash, Node: "synthetic-header-node"}}, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.FinishRange(ctx, head.ID, 2, ""); err != nil {
		t.Fatal(err)
	}
	release()
	origin := executionwitness.Origin{Path: executionwitness.OriginPath, Version: executionwitness.OriginVersion, Sum: executionwitness.OriginSum}
	verifier := executionwitness.Verifier{SHA256: strings.Repeat("f", 64), Origin: origin}
	source := executionwitness.Snapshot{Format: executionwitness.InputFormat, Node: member, ChainID: "7", GenesisHash: genesis, ConfigSHA256: strings.Repeat("c", 64), Blocks: []executionwitness.BlockEvidence{{Index: "0", Hash: genesis}, {Index: "1", Hash: blockHash, Parent: genesis}, {Index: "2", Hash: epochHash, Parent: blockHash}}}
	selector := keccak.Sum256Bytes([]byte("configureValidator(address,bytes,bytes)"))
	input := epochFixtureDigest(selector[:4])
	frame := executionwitness.Frame{Path: []uint32{}, Kind: "CALL", From: member, To: address, Input: input, Selector: "0x" + hex.EncodeToString(selector[:4]), Return: epochFixtureDigest(nil), Gas: "1000", GasUsed: "10", Status: "succeeded", VMError: "none", Effective: true, AccountCodeHash: code, AccountCodeBytes: 100, Observation: "call_hook", Authority: "gov_validator", AuthorityIndex: "0", ABIStatus: "not_reverted"}
	point := executionwitness.Transaction{Index: "1", Ordinal: 0, Hash: txHash, BlockHash: blockHash, From: member, To: address, Input: input, Selector: frame.Selector, GasUsed: "10", ReceiptStatus: "succeeded", Receipt: epochFixtureDigest([]byte{1}), Logs: []executionwitness.Log{}, Frames: []executionwitness.Frame{frame}}
	beforeAccount := executionwitness.ContractStorage{Address: address, CodeHash: code, StorageRoot: "0x" + strings.Repeat("a", 64), Exists: true}
	afterAccount := beforeAccount
	afterAccount.StorageRoot = "0x" + strings.Repeat("b", 64)
	before := executionwitness.RegistryRead{Status: "observed", Reason: "reviewed_runtime", State: &executionwitness.RegistryState{Layout: "wbft-validator-registry/1", Address: address, CodeHash: code, StorageRoot: beforeAccount.StorageRoot, Candidates: []executionwitness.RegistryCandidate{}, WithoutKeys: []string{}}}
	candidate := executionwitness.RegistryCandidate{Address: member, Operator: address, Key: epochFixtureDigest(key)}
	after := executionwitness.RegistryRead{Status: "observed", Reason: "reviewed_runtime", State: &executionwitness.RegistryState{Layout: "wbft-validator-registry/1", Address: address, CodeHash: code, StorageRoot: afterAccount.StorageRoot, Candidates: []executionwitness.RegistryCandidate{candidate}, WithoutKeys: []string{}}}
	var slotInput, value [64]byte
	for i := 12; i < 32; i++ {
		slotInput[i] = 0x22
	}
	slotInput[63] = 0x34
	slot := keccak.Sum256(slotInput[:])
	value[63] = 1
	write := executionwitness.StorageWrite{Address: address, SlotSHA256: epochFixtureDigest(slot[:]).SHA256, Before: epochFixtureDigest(make([]byte, 32)), After: epochFixtureDigest(value[32:]), OwnerCodeHash: code, Frame: 0, Path: []uint32{}, Instruction: &executionwitness.StorageInstruction{PC: "1", CodeReference: address, CodeHash: code}}
	transition := executionwitness.TransactionTransition{Index: "1", Ordinal: 0, Hash: txHash, BlockHash: blockHash, Status: "observed", Reason: "reviewed_runtime_writes", Method: "configureValidator", AccountsBefore: []executionwitness.ContractStorage{beforeAccount}, AccountsAfter: []executionwitness.ContractStorage{afterAccount}, Writes: []executionwitness.StorageWrite{write}, RegistryBefore: before, RegistryAfter: after, Effects: []executionwitness.RegistryEffect{{Kind: "candidate_added", Candidate: member, After: &candidate}}, CauseStatus: "verified_transaction_effect"}
	blocks := []executionwitness.BlockTransition{
		{Index: "0", Genesis: true, BeforeSystem: []executionwitness.ContractStorage{}, BeforeTransactions: []executionwitness.ContractStorage{}, AfterTransactions: []executionwitness.ContractStorage{}, Finalized: []executionwitness.ContractStorage{beforeAccount}},
		{Index: "1", BeforeSystem: []executionwitness.ContractStorage{beforeAccount}, BeforeTransactions: []executionwitness.ContractStorage{beforeAccount}, AfterTransactions: []executionwitness.ContractStorage{afterAccount}, Finalized: []executionwitness.ContractStorage{afterAccount}},
		{Index: "2", BeforeSystem: []executionwitness.ContractStorage{afterAccount}, BeforeTransactions: []executionwitness.ContractStorage{afterAccount}, AfterTransactions: []executionwitness.ContractStorage{afterAccount}, Finalized: []executionwitness.ContractStorage{afterAccount}, EpochRegistry: &after},
	}
	report := executionwitness.TransitionReport{Protocol: executionwitness.TransitionProtocol, Execution: executionwitness.Report{Protocol: executionwitness.Protocol, Origin: origin, Source: source, Transactions: []executionwitness.Transaction{point}}, Blocks: blocks, Transactions: []executionwitness.TransactionTransition{transition}}
	metadata := report.Execution
	metadata.Source.Blocks, metadata.Transactions = []executionwitness.BlockEvidence{}, []executionwitness.Transaction{}
	replay := GovernanceExecutionWitness{DatasetID: gov.ID, Snapshot: strings.Repeat("e", 64), HeadersDataset: &head.ID, HeaderSourceID: head.ID, Source: executionwitness.Projection{Report: metadata, Verifier: verifier}, Blocks: 3, Transactions: 1}
	raw, _ := json.Marshal(replay)
	if _, err = s.pool.Exec(ctx, `INSERT INTO governance_execution_witnesses VALUES($1,$2,$3,$3,$4)`, gov.ID, replay.Snapshot, head.ID, raw); err != nil {
		t.Fatal(err)
	}
	for _, block := range source.Blocks {
		raw, _ = json.Marshal(block)
		if _, err = s.pool.Exec(ctx, `INSERT INTO governance_execution_blocks VALUES($1,$2,$3::numeric,$4)`, gov.ID, replay.Snapshot, block.Index, raw); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ = json.Marshal(point)
	if _, err = s.pool.Exec(ctx, `INSERT INTO governance_execution_transactions VALUES($1,$2,1,0,$3)`, gov.ID, replay.Snapshot, raw); err != nil {
		t.Fatal(err)
	}
	witness := GovernanceTransitionWitness{DatasetID: gov.ID, Snapshot: strings.Repeat("d", 64), ExecutionSnapshot: replay.Snapshot, Source: executionwitness.TransitionProjection{Report: executionwitness.TransitionReport{Protocol: executionwitness.TransitionProtocol, Execution: metadata, Blocks: []executionwitness.BlockTransition{}, Transactions: []executionwitness.TransactionTransition{}}, Verifier: verifier}, Blocks: 3, Transactions: 1}
	f := epochRegistryFixture{gov: gov, head: head, witness: witness, replay: replay, report: report}
	f.insertWitness(t, s, witness)
	var capture GovernanceCapture
	if err = s.pool.QueryRow(ctx, `SELECT info FROM governance_captures WHERE dataset_id=$1`, gov.ID).Scan(&raw); err != nil || json.Unmarshal(raw, &capture) != nil {
		t.Fatal("capture", err)
	}
	capture.Calls = []GovernanceCall{{Ordinal: 1, Request: governance.Request{Method: "wbft_govOps"}, Status: "available"}}
	raw, _ = json.Marshal(capture)
	if _, err = s.pool.Exec(ctx, `UPDATE governance_captures SET info=$2 WHERE dataset_id=$1`, gov.ID, raw); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(governance.Call{Ordinal: 1, Request: governance.Request{Method: "wbft_govOps"}, Status: "available", Data: json.RawMessage(`[]`)})
	if _, err = s.pool.Exec(ctx, `INSERT INTO governance_calls VALUES($1,1,'wbft_govOps',$2)`, gov.ID, raw); err != nil {
		t.Fatal(err)
	}
	op := governance.Operation{BlockHash: &blockHash, Number: "0x1", Tx: 0, TxHash: txHash, Path: []uint32{}, From: member, Instance: address, Input: governance.Bytes{SHA256: input.SHA256, Length: input.Bytes}, Selector: frame.Selector, Effective: true, Result: "success", ResultValue: sourceText("success"), Logs: []governance.Log{}}
	raw, _ = json.Marshal(op)
	if _, err = s.pool.Exec(ctx, `INSERT INTO gov_ops VALUES($1,1,1,'0',1,$2,0,$3)`, gov.ID, address, raw); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f epochRegistryFixture) insertWitness(t *testing.T, s *Store, w GovernanceTransitionWitness) {
	t.Helper()
	ctx := context.Background()
	raw, _ := json.Marshal(w)
	if _, err := s.pool.Exec(ctx, `INSERT INTO governance_transition_witnesses VALUES($1,$2,$3,$4)`, f.gov.ID, w.Snapshot, f.replay.Snapshot, raw); err != nil {
		t.Fatal(err)
	}
	for _, block := range f.report.Blocks {
		raw, _ := json.Marshal(block)
		if _, err := s.pool.Exec(ctx, `INSERT INTO governance_transition_blocks VALUES($1,$2,$3::numeric,$4)`, f.gov.ID, w.Snapshot, block.Index, raw); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ = json.Marshal(f.report.Transactions[0])
	if _, err := s.pool.Exec(ctx, `INSERT INTO governance_transition_transactions VALUES($1,$2,1,0,$3)`, f.gov.ID, w.Snapshot, raw); err != nil {
		t.Fatal(err)
	}
}

func TestEpochRegistryPagesKeepSourceScopeAndOperationLinks(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	f := newEpochRegistryFixture(t, s)
	first, err := s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", 0, 1, "")
	if err != nil || first.Total != 2 || len(first.Rows) != 1 || first.Rows[0].Kind != "epoch_state" || first.Rows[0].Status != "matched" || first.Next == nil || *first.Next != 1 {
		t.Fatal("first page", first, err)
	}
	second, err := s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", *first.Next, 1, first.Snapshot)
	if err != nil || second.Next != nil || len(second.Rows) != 1 || second.Rows[0].Status != "verified_retained_registry_effect" || len(second.Rows[0].Operations) != 1 || second.Rows[0].Operations[0].EntryOrdinal != 1 {
		t.Fatal("linked effect", second, err)
	}
	full, err := s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", 0, 20, first.Snapshot)
	if err != nil || !reflect.DeepEqual(full.Rows, append(first.Rows, second.Rows...)) {
		t.Fatal("page order changed with page size", err)
	}
	if _, err = s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", 0, 1, strings.Repeat("0", 64)); !errors.Is(err, ErrEpochRegistrySnapshot) {
		t.Fatal("wrong snapshot accepted", err)
	}
	ordinary, err := s.EpochRegistryEffects(ctx, f.gov.NetworkID, "1", 0, 1, "")
	if err != nil || ordinary.Status != "not_epoch" || ordinary.Total != 0 {
		t.Fatal("ordinary block became an epoch", ordinary, err)
	}
	for _, index := range []string{"02", "-1", "18446744073709551616"} {
		if _, err = s.EpochRegistryEffects(ctx, f.gov.NetworkID, index, 0, 1, ""); !errors.Is(err, ErrGovernanceQuery) {
			t.Fatal("noncanonical index accepted", index, err)
		}
	}
	if _, err = s.EpochRegistryEffects(ctx, f.gov.NetworkID, "3", 0, 1, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing header accepted", err)
	}
	copy := f.witness
	copy.Snapshot = strings.Repeat("a", 64)
	f.insertWitness(t, s, copy)
	if _, err = s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", 1, 1, first.Snapshot); !errors.Is(err, ErrEpochRegistrySnapshot) {
		t.Fatal("new witness did not fence the next page", err)
	}
}

func TestEpochRegistryPagesRecheckOriginalOperationAndHeaderSource(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	f := newEpochRegistryFixture(t, s)
	first, err := s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", 0, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	var originalOp, originalMetadata []byte
	if err = s.pool.QueryRow(ctx, `SELECT row_ FROM gov_ops WHERE dataset_id=$1`, f.gov.ID).Scan(&originalOp); err != nil {
		t.Fatal(err)
	}
	if err = s.pool.QueryRow(ctx, `SELECT metadata FROM datasets WHERE id=$1`, f.head.ID).Scan(&originalMetadata); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, mutate, restore, reason string
		id                            int64
		value                         []byte
	}{
		{"wrong original transaction", `UPDATE gov_ops SET row_=jsonb_set(row_,'{tx_hash}','"different"') WHERE dataset_id=$1`, `UPDATE gov_ops SET row_=$2 WHERE dataset_id=$1`, "operation_mismatch", f.gov.ID, originalOp},
		{"nested source only", `UPDATE gov_ops SET row_=jsonb_set(row_,'{path}','[0]') WHERE dataset_id=$1`, `UPDATE gov_ops SET row_=$2 WHERE dataset_id=$1`, "operation_unavailable", f.gov.ID, originalOp},
		{"original configuration changed", `UPDATE datasets SET metadata='{}' WHERE id=$1`, `UPDATE datasets SET metadata=$2 WHERE id=$1`, "source_unbound", f.head.ID, originalMetadata},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := s.pool.Exec(ctx, test.mutate, test.id); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := s.pool.Exec(ctx, test.restore, test.id, test.value); err != nil {
					t.Error(err)
				}
			})
			page, err := s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", 1, 1, first.Snapshot)
			if err != nil || len(page.Rows) != 1 || page.Rows[0].Status != "unverified" || page.Rows[0].Reason != test.reason {
				t.Fatal("current source changes were not rechecked on a later page", page, err)
			}
		})
	}
	meta := []byte(`{"config_sha256":"` + strings.Repeat("c", 64) + `"}`)
	alternate, release, err := s.BeginRange(ctx, NetworkKey{ChainID: "7", GenesisHash: f.replay.Source.Report.Source.GenesisHash}, "alternate-epoch-headers", meta)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.pool.Query(ctx, `SELECT fact FROM heights WHERE network_id=$1 ORDER BY index_`, f.gov.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (headers.Fact, error) {
		var raw []byte
		var fact headers.Fact
		if err := row.Scan(&raw); err != nil {
			return fact, err
		}
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
	if err = s.FinishRange(ctx, alternate.ID, 2, ""); err != nil {
		t.Fatal(err)
	}
	release()
	if _, err = s.DeleteDataset(ctx, f.gov.NetworkID, f.head.ID, f.head.Name); err != nil {
		t.Fatal(err)
	}
	page, err := s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", 1, 1, first.Snapshot)
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Status != "unverified" || page.Rows[0].Binding != "source_unavailable" || page.Rows[0].HeaderSourceID != f.head.ID || page.Rows[0].HeadersDataset != nil || page.Rows[0].Effect == nil || page.Rows[0].Effect.Retention.Status != "verified_retained_registry_effect" {
		t.Fatal("matching alternate headers replaced the removed original dependency", page, err)
	}
	if _, err = s.DeleteDataset(ctx, f.gov.NetworkID, f.gov.ID, f.gov.Name); err != nil {
		t.Fatal(err)
	}
	if _, err = s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", 0, 1, first.Snapshot); !errors.Is(err, ErrEpochRegistrySnapshot) {
		t.Fatal("capture deletion did not invalidate its source-set cursor", err)
	}
	page, err = s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", 0, 1, "")
	if err != nil || page.Total != 0 || len(page.Rows) != 0 {
		t.Fatal("deleted owner retained registry evidence", page, err)
	}
}

func TestEpochRegistryPagesPreserveWitnessConflictAndTruncation(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		t.Run(fmt.Sprint(truncated), func(t *testing.T) {
			s, _ := testStore(t)
			ctx := context.Background()
			if _, err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			f := newEpochRegistryFixture(t, s)
			count := 1
			if truncated {
				count = 20
			}
			for i := range count {
				copy := f.witness
				copy.Snapshot = fmt.Sprintf("%064x", i+1)
				f.insertWitness(t, s, copy)
				if !truncated {
					if _, err := s.pool.Exec(ctx, `UPDATE governance_transition_transactions SET point=jsonb_set(point,'{method}','"changeMember"') WHERE dataset_id=$1 AND snapshot=$2`, f.gov.ID, copy.Snapshot); err != nil {
						t.Fatal(err)
					}
				}
			}
			var offset int64
			var snapshot string
			effects := 0
			for {
				page, err := s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", offset, 4, snapshot)
				if err != nil {
					t.Fatal(err)
				}
				snapshot = page.Snapshot
				for _, row := range page.Rows {
					if row.Kind != "transaction_effect" {
						continue
					}
					effects++
					if row.Status != "unverified" || len(row.Operations) != 1 || row.Operations[0].Status != "ambiguous" || row.Operations[0].ComparisonsTruncated != truncated {
						t.Fatal("a convenient witness suppressed conflicting or truncated evidence", row)
					}
				}
				if page.Next == nil {
					break
				}
				offset = *page.Next
			}
			if effects != count+1 {
				t.Fatal("pagination did not reach all effect witnesses", effects)
			}
		})
	}
}

func TestEpochRegistryPagesDoNotExposeOtherVisibility(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	f := newEpochRegistryFixture(t, s)
	visibility := "private"
	if privacy.Visibility() == visibility {
		visibility = "public"
	}
	if _, err := s.pool.Exec(ctx, `UPDATE datasets SET visibility=$2 WHERE id=$1`, f.gov.ID, visibility); err != nil {
		t.Fatal(err)
	}
	page, err := s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", 0, 20, "")
	if err != nil || page.Total != 0 || len(page.Rows) != 0 {
		t.Fatal("invisible capture exposed transition evidence", page, err)
	}
	if _, err = s.pool.Exec(ctx, `UPDATE networks SET visibility=$2 WHERE id=$1`, f.gov.NetworkID, visibility); err != nil {
		t.Fatal(err)
	}
	if _, err = s.EpochRegistryEffects(ctx, f.gov.NetworkID, "2", 0, 20, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("invisible network exposed its canonical header", err)
	}
}
