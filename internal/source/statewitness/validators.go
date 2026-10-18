package statewitness

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const ValidatorLayout = "wbft-validator-keys/1"
const MaxCandidates = 4096

var (
	ErrLayout         = errors.New("unsupported validator-state layout")
	ErrValidatorState = errors.New("incomplete or inconsistent validator-state evidence")
	// Interpretation is restricted to this reviewed runtime, not merely to a
	// caller's layout label or the presence of similarly named storage slots.
	validatorRuntime = common.HexToHash("0xb5ce66a9f8c1a08247521c60191f8b11e31e472d8dc26ea163e66de307303dac")
)

type CandidateKey struct {
	Address   string `json:"address"`
	KeyBytes  int    `json:"key_bytes"`
	KeySHA256 string `json:"key_sha256"`
}

// ValidatorState authenticates a complete candidate/key read set at one
// contract. It does not establish the configured authority, an epoch's full
// consensus validity, or which transaction caused a change.
type ValidatorState struct {
	Layout      string         `json:"layout"`
	Contract    string         `json:"contract"`
	CodeHash    string         `json:"code_hash"`
	StateRoot   string         `json:"state_root"`
	StorageRoot string         `json:"storage_root"`
	Slots       int            `json:"slots"`
	Candidates  []CandidateKey `json:"candidates"`
	WithoutKeys []string       `json:"without_keys"`
}

func DecodeValidatorState(account VerifiedAccount) (ValidatorState, error) {
	if account.codeHash != validatorRuntime {
		return ValidatorState{}, ErrLayout
	}
	used := map[common.Hash]bool{}
	word := func(slot common.Hash) (common.Hash, bool) {
		value, ok := account.Value(slot)
		if ok {
			used[slot] = true
		}
		return value, ok
	}
	// The reviewed layout uses an enumerable address set at slot 0x33
	// (array and one-based positions) and a bytes mapping at slot 0x37.
	array := common.HexToHash("0x33")
	positions := common.HexToHash("0x34")
	keys := common.HexToHash("0x37")
	length, ok := word(array)
	if !ok || !length.Big().IsUint64() || length.Big().Uint64() > MaxCandidates {
		return ValidatorState{}, ErrValidatorState
	}
	count := length.Big().Uint64()
	out := ValidatorState{Layout: ValidatorLayout, Contract: strings.ToLower(account.address.Hex()), CodeHash: account.codeHash.Hex(), StateRoot: account.stateRoot.Hex(), StorageRoot: account.storageRoot.Hex(), Slots: account.Slots(), Candidates: []CandidateKey{}, WithoutKeys: []string{}}
	seen := map[common.Address]bool{}
	data := crypto.Keccak256Hash(array[:])
	for i := uint64(0); i < count; i++ {
		entry, ok := word(addSlot(data, i))
		if !ok || entry.Big().BitLen() > 160 {
			return ValidatorState{}, ErrValidatorState
		}
		address := common.BytesToAddress(entry[12:])
		if address == (common.Address{}) || seen[address] {
			return ValidatorState{}, ErrValidatorState
		}
		seen[address] = true
		position, ok := word(mappingSlot(positions, address))
		if !ok || position != common.BigToHash(new(big.Int).SetUint64(i+1)) {
			return ValidatorState{}, ErrValidatorState
		}
		head := mappingSlot(keys, address)
		encoded, ok := word(head)
		if !ok {
			return ValidatorState{}, ErrValidatorState
		}
		key := []byte{}
		if encoded != (common.Hash{}) {
			// Solidity long bytes encode length*2+1 in the head. The
			// supported contract admits exactly 48-byte public keys.
			if encoded != common.HexToHash("0x61") {
				return ValidatorState{}, ErrValidatorState
			}
			start := crypto.Keccak256Hash(head[:])
			first, ok1 := word(start)
			second, ok2 := word(addSlot(start, 1))
			if !ok1 || !ok2 {
				return ValidatorState{}, ErrValidatorState
			}
			key = append(key, first[:]...)
			key = append(key, second[:16]...)
			if _, err := bls.DecodePublicKey(key); err != nil {
				return ValidatorState{}, ErrValidatorState
			}
		}
		label := strings.ToLower(address.Hex())
		sum := sha256.Sum256(key)
		out.Candidates = append(out.Candidates, CandidateKey{Address: label, KeyBytes: len(key), KeySHA256: hex.EncodeToString(sum[:])})
		if len(key) == 0 {
			out.WithoutKeys = append(out.WithoutKeys, label)
		}
	}
	if len(used) != account.Slots() {
		return ValidatorState{}, ErrValidatorState
	}
	return out, nil
}

func mappingSlot(base common.Hash, address common.Address) common.Hash {
	return crypto.Keccak256Hash(common.LeftPadBytes(address[:], 32), base[:])
}

func addSlot(base common.Hash, offset uint64) common.Hash {
	// BytesToHash retains the low 256 bits, as Solidity slot arithmetic does.
	return common.BigToHash(new(big.Int).Add(base.Big(), new(big.Int).SetUint64(offset)))
}
