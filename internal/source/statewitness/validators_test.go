package statewitness

import (
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func validatorExample(t *testing.T) VerifiedAccount {
	t.Helper()
	seed := make([]byte, 32)
	seed[31] = 1
	sk, err := bls.DeriveSecretKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	key := sk.PublicKey().Bytes()
	a := VerifiedAccount{address: common.HexToAddress("0x1234"), codeHash: validatorRuntime, stateRoot: common.HexToHash("0x11"), storageRoot: common.HexToHash("0x22"), values: map[common.Hash]common.Hash{}}
	array, positions, keys := common.HexToHash("0x33"), common.HexToHash("0x34"), common.HexToHash("0x37")
	a.values[array] = common.HexToHash("0x02")
	data := crypto.Keccak256Hash(array[:])
	for i := uint64(0); i < 2; i++ {
		address := common.BigToAddress(new(big.Int).SetUint64(i + 1))
		a.values[addSlot(data, i)] = common.BytesToHash(address[:])
		a.values[mappingSlot(positions, address)] = common.BigToHash(new(big.Int).SetUint64(i + 1))
		head := mappingSlot(keys, address)
		if i == 1 {
			a.values[head] = common.Hash{}
			continue
		}
		a.values[head] = common.HexToHash("0x61")
		start := crypto.Keccak256Hash(head[:])
		a.values[start] = common.BytesToHash(key[:32])
		var tail common.Hash
		copy(tail[:], key[32:])
		a.values[addSlot(start, 1)] = tail
	}
	return a
}

func TestValidatorReadSet(t *testing.T) {
	account := validatorExample(t)
	state, err := DecodeValidatorState(account)
	if err != nil {
		t.Fatal(err)
	}
	if state.Layout != ValidatorLayout || state.Slots != 9 || len(state.Candidates) != 2 || state.Candidates[0].KeyBytes != 48 || state.Candidates[1].KeyBytes != 0 || len(state.WithoutKeys) != 1 || state.WithoutKeys[0] != common.HexToAddress("0x02").Hex() {
		t.Fatal("authenticated candidate/key interpretation differs", state)
	}
	// The lower half of the final storage word is outside a 48-byte value.
	// Solidity's byte length, rather than incidental padding, defines the key.
	head := mappingSlot(common.HexToHash("0x37"), common.HexToAddress("0x01"))
	data := crypto.Keccak256Hash(head[:])
	last := addSlot(data, 1)
	value := account.values[last]
	value[31] = 0x7f
	account.values[last] = value
	withPadding, err := DecodeValidatorState(account)
	if err != nil || withPadding.Candidates[0] != state.Candidates[0] {
		t.Fatal("unused storage bits changed the public key", err)
	}
}

func TestProvenEmptyCandidateSet(t *testing.T) {
	a := VerifiedAccount{codeHash: validatorRuntime, values: map[common.Hash]common.Hash{common.HexToHash("0x33"): {}}}
	state, err := DecodeValidatorState(a)
	if err != nil || len(state.Candidates) != 0 || len(state.WithoutKeys) != 0 || state.Slots != 1 {
		t.Fatal("proven empty candidate set became missing evidence", err)
	}
}

func TestRejectIncompleteOrUnknownValidatorState(t *testing.T) {
	array, keys := common.HexToHash("0x33"), common.HexToHash("0x37")
	head := mappingSlot(keys, common.HexToAddress("0x01"))
	data := crypto.Keccak256Hash(head[:])
	tests := map[string]func(*VerifiedAccount){
		"unknown runtime": func(a *VerifiedAccount) { a.codeHash = common.Hash{} },
		"missing length":  func(a *VerifiedAccount) { delete(a.values, array) },
		"oversized set":   func(a *VerifiedAccount) { a.values[array] = common.BigToHash(big.NewInt(MaxCandidates + 1)) },
		"missing key":     func(a *VerifiedAccount) { delete(a.values, head) },
		"unsupported key length": func(a *VerifiedAccount) {
			a.values[head] = common.HexToHash("0x63")
		},
		"missing data": func(a *VerifiedAccount) { delete(a.values, addSlot(data, 1)) },
		"invalid BLS key": func(a *VerifiedAccount) {
			a.values[data] = common.Hash{}
			a.values[addSlot(data, 1)] = common.Hash{}
		},
		"missing position": func(a *VerifiedAccount) {
			delete(a.values, mappingSlot(common.HexToHash("0x34"), common.HexToAddress("0x02")))
		},
		"incorrect position": func(a *VerifiedAccount) {
			a.values[mappingSlot(common.HexToHash("0x34"), common.HexToAddress("0x02"))] = common.HexToHash("0x01")
		},
		"duplicate candidate": func(a *VerifiedAccount) {
			start := crypto.Keccak256Hash(array[:])
			a.values[addSlot(start, 1)] = common.HexToHash("0x01")
		},
		"extra slot": func(a *VerifiedAccount) { a.values[common.HexToHash("0xff")] = common.Hash{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			account := validatorExample(t)
			mutate(&account)
			if _, err := DecodeValidatorState(account); err == nil {
				t.Fatal("unknown or incomplete state interpreted as verified keys")
			}
		})
	}
}
