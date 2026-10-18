package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/systemcontracts"
	blst "github.com/supranational/blst/bindings/go"
)

func registryFixture(t *testing.T) (*state.StateDB, common.Address, common.Address, common.Address, []byte) {
	t.Helper()
	mem := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { _ = mem.Close() })
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(mem), nil)
	if err != nil {
		t.Fatal(err)
	}
	contract, candidate, operator := common.HexToAddress("0x70000"), common.HexToAddress("0x80000"), common.HexToAddress("0x90000")
	st.SetCode(contract, common.FromHex(systemcontracts.GovValidatorContractV1))
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key := new(blst.P1Affine).From(blst.KeyGen(seed)).Compress()
	st.SetState(contract, stateSlot(0x33), stateSlot(1))
	array := stateSlot(0x33)
	st.SetState(contract, crypto.Keccak256Hash(array[:]), common.BytesToHash(candidate[:]))
	st.SetState(contract, addressSlot(candidate, 0x34), stateSlot(1))
	st.SetState(contract, addressSlot(candidate, 0x35), common.BytesToHash(operator[:]))
	st.SetState(contract, addressSlot(operator, 0x36), common.BytesToHash(candidate[:]))
	head := addressSlot(candidate, 0x37)
	first := crypto.Keccak256Hash(head[:])
	st.SetState(contract, head, stateSlot(97))
	st.SetState(contract, first, common.BytesToHash(key[:32]))
	last := common.Hash{}
	copy(last[:16], key[32:])
	st.SetState(contract, offsetSlot(first, 1), last)
	reverse := stateSlot(0x38)
	st.SetState(contract, crypto.Keccak256Hash(key, reverse[:]), common.BytesToHash(candidate[:]))
	return st, contract, candidate, operator, key
}

func TestRegistryReadCompleteKeySet(t *testing.T) {
	st, contract, candidate, operator, key := registryFixture(t)
	got, err := readRegistry(context.Background(), st, contract, true)
	if err != nil || len(got.Candidates) != 1 || got.Candidates[0].Address != strings.ToLower(candidate.Hex()) || got.Candidates[0].Operator != strings.ToLower(operator.Hex()) || got.Candidates[0].Key != digest(key) || len(got.WithoutKeys) != 0 {
		t.Fatal("complete reviewed registry differs", got, err)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), common.Bytes2Hex(key)) {
		t.Fatal("raw key leaked from registry projection")
	}
	head := addressSlot(candidate, 0x37)
	st.SetState(contract, head, common.Hash{})
	got, err = readRegistry(context.Background(), st, contract, true)
	if err != nil || len(got.WithoutKeys) != 1 || got.Candidates[0].Key != digest(nil) {
		t.Fatal("explicit empty key became an invalid point or disappeared", got, err)
	}
}

func TestRegistryReadRejectsUnsupportedState(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*state.StateDB, common.Address, common.Address, common.Address)
	}{
		{"wrong position", func(s *state.StateDB, a, c, o common.Address) { s.SetState(a, addressSlot(c, 0x34), stateSlot(2)) }},
		{"operator mismatch", func(s *state.StateDB, a, c, o common.Address) { s.SetState(a, addressSlot(o, 0x36), common.Hash{}) }},
		{"invalid key length", func(s *state.StateDB, a, c, o common.Address) { s.SetState(a, addressSlot(c, 0x37), stateSlot(65)) }},
		{"invalid compressed key", func(s *state.StateDB, a, c, o common.Address) {
			h := addressSlot(c, 0x37)
			start := crypto.Keccak256Hash(h[:])
			s.SetState(a, start, common.Hash{})
			s.SetState(a, offsetSlot(start, 1), common.Hash{})
		}},
		{"unbounded set", func(s *state.StateDB, a, c, o common.Address) {
			s.SetState(a, stateSlot(0x33), stateSlot(maxRegistryCandidates+1))
		}},
		{"unknown runtime", func(s *state.StateDB, a, c, o common.Address) { s.SetCode(a, []byte{0}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			st, a, c, o, _ := registryFixture(t)
			test.mutate(st, a, c, o)
			if _, err := readRegistry(context.Background(), st, a, true); err == nil {
				t.Fatal("unsupported registry accepted")
			}
		})
	}
	st, a, _, _, _ := registryFixture(t)
	read := registryRead(context.Background(), st, params.SystemContracts{GovValidator: &params.SystemContract{Address: a, Version: "v2"}}, true)
	if read.Status != "unavailable" || read.Reason != "unsupported_runtime" || read.State != nil {
		t.Fatal("declared unknown version interpreted as reviewed state")
	}
}

func TestProposalReadPackedStateAndDigest(t *testing.T) {
	st, address, _, proposer, _ := registryFixture(t)
	id := big.NewInt(7)
	base := mapSlot(common.BigToHash(id), 7)
	st.SetState(address, base, crypto.Keccak256Hash([]byte("ACTION_REMOVE_MEMBER")))
	st.SetState(address, offsetSlot(base, 1), stateSlot(2))
	st.SetState(address, offsetSlot(base, 3), stateSlot(10))
	st.SetState(address, offsetSlot(base, 4), stateSlot(20))
	packed := common.BytesToHash(proposer[:])
	binary.BigEndian.PutUint32(packed[8:12], 3)
	binary.BigEndian.PutUint32(packed[4:8], 2)
	binary.BigEndian.PutUint32(packed[:4], 1)
	st.SetState(address, offsetSlot(base, 5), packed)
	st.SetState(address, offsetSlot(base, 6), stateSlot(3))
	st.SetState(address, mapSlot(common.BigToHash(id), 10), stateSlot(1))
	data := append(common.LeftPadBytes(proposer[:], 32), stateSlot(2).Bytes()...)
	head := offsetSlot(base, 7)
	first := crypto.Keccak256Hash(head[:])
	st.SetState(address, head, stateSlot(129))
	st.SetState(address, first, common.BytesToHash(data[:32]))
	st.SetState(address, offsetSlot(first, 1), common.BytesToHash(data[32:]))
	got, err := readProposal(context.Background(), st, address, validatorProfile.code, id)
	if err != nil || got.Status != "3" || got.ID != "7" || got.Proposer != strings.ToLower(proposer.Hex()) || got.RequiredApprovals != 3 || got.Approved != 2 || got.Rejected != 1 || got.ExecutionCount != "1" || got.CallData != digest(data) {
		t.Fatal("packed proposal or calldata digest differs", got, err)
	}
	st.SetState(address, offsetSlot(base, 6), stateSlot(8))
	if _, err := readProposal(context.Background(), st, address, validatorProfile.code, id); err == nil {
		t.Fatal("unknown proposal state accepted")
	}
}

func TestSystemPhaseComparisonUsesActualStorageTarget(t *testing.T) {
	a := ContractStorage{Address: "one", CodeHash: "code", StorageRoot: "root", Exists: true}
	b := ContractStorage{Address: "two", CodeHash: "code", StorageRoot: "old", Exists: true}
	changed := b
	changed.StorageRoot = "new"
	if storagePhaseChanged([]ContractStorage{a, b}, []ContractStorage{a, changed}, a.Address) {
		t.Fatal("unrelated target change invalidated an unchanged storage target")
	}
	if !storagePhaseChanged([]ContractStorage{a, b}, []ContractStorage{a, changed}, b.Address) {
		t.Fatal("changed target storage was missed")
	}
}

func TestUnavailableRegistryDoesNotClaimNoChange(t *testing.T) {
	observer := storageFixture(t, false, false, false)
	frames, err := observer.trace.projection()
	if err != nil {
		t.Fatal(err)
	}
	parent := common.HexToAddress("0x10000")
	point := &transitionCapture{ctx: context.Background()}
	tx := types.NewTx(&types.LegacyTx{To: &parent})
	if err := point.transaction(&types.Header{Number: big.NewInt(1)}, tx, 0, params.SystemContracts{GovValidator: &params.SystemContract{Address: parent, Version: "v1"}}, observer.StateDB, observer, Transaction{Frames: frames, ReceiptStatus: "succeeded"}, true); err != nil {
		t.Fatal(err)
	}
	if len(point.transactions) != 1 || point.transactions[0].RegistryBefore.Status != "unavailable" || point.transactions[0].Reason != "unavailable_registry_state" || point.transactions[0].CauseStatus != "unestablished" {
		t.Fatal("unavailable registry was presented as proven unchanged")
	}
}
