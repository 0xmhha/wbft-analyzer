package executionwitness

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

func transitionFixture() (TransitionReport, snapshot, Origin) {
	address := "0x" + strings.Repeat("1", 40)
	operator := "0x" + strings.Repeat("2", 40)
	root := "0x" + strings.Repeat("a", 64)
	account := ContractStorage{Address: address, CodeHash: validatorCodeHash, StorageRoot: root, Exists: true}
	accounts := []ContractStorage{account}
	afterAccount := account
	afterAccount.StorageRoot = "0x" + strings.Repeat("b", 64)
	afterAccounts := []ContractStorage{afterAccount}
	read := RegistryRead{Status: "observed", Reason: "reviewed_runtime", State: &RegistryState{Layout: registryLayout, Address: address, CodeHash: validatorCodeHash, StorageRoot: root, Candidates: []RegistryCandidate{}, WithoutKeys: []string{}}}
	key := []byte(strings.Repeat("k", 48))
	added := read
	st := *read.State
	st.StorageRoot = afterAccount.StorageRoot
	st.Candidates = []RegistryCandidate{{Address: operator, Operator: address, Key: digest(key)}}
	added.State = &st
	method := keccak.Sum256Bytes([]byte("configureValidator(address,bytes,bytes)"))
	origin := Origin{Path: OriginPath, Version: OriginVersion, Sum: OriginSum}
	blocks := []BlockEvidence{{Index: "0", Hash: root}, {Index: "1", Hash: root}, {Index: "2", Hash: root}}
	source := Snapshot{ChainID: "7", Blocks: blocks}
	frame := Frame{Path: []uint32{}, Kind: "CALL", From: operator, To: address, Input: digest(method[:4]), Selector: "0x" + hex.EncodeToString(method[:4]), Return: digest(nil), Gas: "1000", GasUsed: "10", Status: "succeeded", VMError: "none", Effective: true, AccountCodeHash: validatorCodeHash, AccountCodeBytes: 100, Observation: "call_hook", Authority: "gov_validator", AuthorityIndex: "0", ABIStatus: "not_reverted"}
	tx := Transaction{Index: "1", Ordinal: 0, Hash: root, BlockHash: root, From: operator, To: address, Input: frame.Input, Selector: frame.Selector, GasUsed: "10", ReceiptStatus: "succeeded", Receipt: digest([]byte{1}), Logs: []Log{}, Frames: []Frame{frame}}
	write := StorageWrite{Address: address, SlotSHA256: digest([]byte("slot")).SHA256, Before: digest(make([]byte, 32)), After: digest([]byte(strings.Repeat("v", 32))), OwnerCodeHash: validatorCodeHash, Frame: 0, Path: []uint32{}, Instruction: &StorageInstruction{PC: "1", CodeReference: address, CodeHash: validatorCodeHash}}
	point := TransactionTransition{Index: "1", Hash: root, BlockHash: root, Status: "observed", Reason: "reviewed_runtime_writes", Method: "configureValidator", AccountsBefore: accounts, AccountsAfter: afterAccounts, Writes: []StorageWrite{write}, RegistryBefore: read, RegistryAfter: added, Effects: expectedRegistryEffects(read, added), CauseStatus: "verified_transaction_effect"}
	phase := func(index string) BlockTransition {
		return BlockTransition{Index: index, BeforeSystem: accounts, BeforeTransactions: accounts, AfterTransactions: accounts, Finalized: accounts}
	}
	genesis := phase("0")
	genesis.Genesis = true
	genesis.BeforeSystem = []ContractStorage{}
	genesis.BeforeTransactions = []ContractStorage{}
	genesis.AfterTransactions = []ContractStorage{}
	epoch := phase("2")
	epoch.BeforeSystem = afterAccounts
	epoch.BeforeTransactions = afterAccounts
	epoch.AfterTransactions = afterAccounts
	epoch.Finalized = afterAccounts
	epoch.EpochRegistry = &added
	changed := phase("1")
	changed.AfterTransactions = afterAccounts
	changed.Finalized = afterAccounts
	report := TransitionReport{Protocol: TransitionProtocol, Execution: Report{Protocol: Protocol, Origin: origin, Source: source, Transactions: []Transaction{tx}}, Blocks: []BlockTransition{genesis, changed, epoch}, Transactions: []TransactionTransition{point}}
	var candidate types.Address
	copy(candidate[:], []byte(strings.Repeat("\x22", 20)))
	info := &types.EpochInfo{Candidates: []types.Candidate{{Addr: candidate}}, Validators: []uint32{0}, BLSPublicKeys: [][]byte{key}}
	s := snapshot{source: source, extraValid: map[string]bool{"0": true, "1": true, "2": true}, epochs: map[string]*types.EpochInfo{"2": info}, transactions: []expectedTransaction{{index: "1", ordinal: 0, hash: root, blockHash: root}}}
	return report, s, origin
}

func cloneTransitions(t *testing.T, report TransitionReport) TransitionReport {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var copy TransitionReport
	if err = json.Unmarshal(raw, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestTransitionBundleRefusesJSONAndOwnsProjection(t *testing.T) {
	var bundle TransitionBundle
	if err := json.Unmarshal([]byte(`{"report":{}}`), &bundle); !errors.Is(err, ErrSource) {
		t.Fatal("untrusted bundle accepted", err)
	}
	report, _, _ := transitionFixture()
	bundle = TransitionBundle{value: TransitionProjection{Report: report}}
	copy := bundle.Projection()
	copy.Report.Transactions[0].Writes[0].Path = append(copy.Report.Transactions[0].Writes[0].Path, 1)
	copy.Report.Transactions[0].RegistryAfter.State.Candidates[0].Address = "changed"
	if !reflect.DeepEqual(bundle.Projection().Report, report) {
		t.Fatal("projection mutated original evidence")
	}
}

func TestTransitionRegistryOrderIsAnEffect(t *testing.T) {
	report, _, _ := transitionFixture()
	before := report.Transactions[0].RegistryAfter
	other := before.State.Candidates[0]
	other.Address = "0x" + strings.Repeat("3", 40)
	before.State.Candidates = append(before.State.Candidates, other)
	after := before
	state := *before.State
	state.Candidates = []RegistryCandidate{other, before.State.Candidates[0]}
	after.State = &state
	effects := expectedRegistryEffects(before, after)
	if len(effects) != 1 || effects[0].Kind != "candidate_order_changed" || effects[0].Candidate != "" || effects[0].Before != nil || effects[0].After != nil {
		t.Fatal("candidate order difference lost", effects)
	}
}

func TestTransitionWireAndSourceBindings(t *testing.T) {
	report, source, origin := transitionFixture()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeTransitions(raw, source, origin); err != nil {
		t.Fatal("complete bound transition refused", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*TransitionReport)
	}{
		{"changed source", func(r *TransitionReport) { r.Execution.Source.Manifest = digest([]byte("different")) }},
		{"changed transaction", func(r *TransitionReport) { r.Transactions[0].Hash = "0x" + strings.Repeat("b", 64) }},
		{"missing phase", func(r *TransitionReport) { r.Blocks[1].AfterTransactions = nil }},
		{"changed before root", func(r *TransitionReport) {
			r.Transactions[0].AccountsBefore[0].StorageRoot = "0x" + strings.Repeat("b", 64)
		}},
		{"changed final root", func(r *TransitionReport) {
			r.Blocks[1].AfterTransactions[0].StorageRoot = "0x" + strings.Repeat("c", 64)
		}},
		{"invented effect", func(r *TransitionReport) { r.Transactions[0].Effects[0].Candidate = "0x" + strings.Repeat("3", 40) }},
		{"missing effective write", func(r *TransitionReport) { r.Transactions[0].Writes = []StorageWrite{} }},
		{"missing instruction", func(r *TransitionReport) { r.Transactions[0].Writes[0].Instruction = nil }},
		{"wrong owner", func(r *TransitionReport) { r.Transactions[0].Writes[0].Address = "0x" + strings.Repeat("3", 40) }},
		{"wrong frame", func(r *TransitionReport) { r.Transactions[0].Writes[0].Frame = 1 }},
		{"wrong opcode code", func(r *TransitionReport) {
			r.Transactions[0].Writes[0].Instruction.CodeHash = "0x" + strings.Repeat("0", 64)
		}},
		{"wrong method", func(r *TransitionReport) { r.Transactions[0].Method = "executeProposal" }},
		{"unknown runtime", func(r *TransitionReport) {
			r.Transactions[0].RegistryAfter.State.CodeHash = "0x" + strings.Repeat("0", 64)
		}},
		{"missing epoch", func(r *TransitionReport) { r.Blocks[2].EpochRegistry = nil }},
		{"epoch candidate mismatch", func(r *TransitionReport) {
			r.Blocks[2].EpochRegistry.State.Candidates[0].Address = "0x" + strings.Repeat("3", 40)
		}},
		{"epoch key mismatch", func(r *TransitionReport) {
			r.Blocks[2].EpochRegistry.State.Candidates[0].Key = digest([]byte(strings.Repeat("x", 48)))
		}},
		{"unpaired proposal", func(r *TransitionReport) { r.Transactions[0].ProposalBefore = &ProposalState{} }},
		{"unknown cause", func(r *TransitionReport) { r.Transactions[0].CauseStatus = "claimed" }},
		{"system overlap", func(r *TransitionReport) { r.Blocks[1].Finalized[0].StorageRoot = "0x" + strings.Repeat("c", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := cloneTransitions(t, report)
			test.mutate(&copy)
			encoded, err := json.Marshal(copy)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := decodeTransitions(encoded, source, origin); err == nil || got.Protocol != "" {
				t.Fatal("unbound or malformed transition admitted", err)
			}
		})
	}
	for _, test := range []struct {
		name     string
		old, new string
	}{
		{"missing false field", `"genesis":false,`, ``},
		{"null false field", `"genesis":false`, `"genesis":null`},
		{"case alias", `"cause_status":`, `"Cause_Status":`},
		{"duplicate key", `"protocol":"wbft-governance-transitions/1"`, `"protocol":"wbft-governance-transitions/1","protocol":"wbft-governance-transitions/1"`},
		{"unknown field", `"genesis":false`, `"genesis":false,"helper":"untrusted"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			altered := strings.Replace(string(raw), test.old, test.new, 1)
			if altered == string(raw) {
				t.Fatal("mutation did not apply")
			}
			if got, err := decodeTransitions([]byte(altered), source, origin); err == nil || got.Protocol != "" {
				t.Fatal("ambiguous wire assertion admitted")
			}
		})
	}
}
