package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	blst "github.com/supranational/blst/bindings/go"
)

const maxRegistryCandidates = 4096

func stateSlot(n uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(n)) }
func mapSlot(key common.Hash, n uint64) common.Hash {
	base := stateSlot(n)
	return crypto.Keccak256Hash(key[:], base[:])
}
func addressSlot(address common.Address, n uint64) common.Hash {
	return mapSlot(common.BytesToHash(address[:]), n)
}
func offsetSlot(base common.Hash, n uint64) common.Hash {
	return common.BigToHash(new(big.Int).Add(base.Big(), new(big.Int).SetUint64(n)))
}
func storedAddress(value common.Hash) (common.Address, error) {
	if !bytes.Equal(value[:12], make([]byte, 12)) {
		return common.Address{}, ErrInput
	}
	return common.BytesToAddress(value[12:]), nil
}

func readStoredBytes(ctx context.Context, st *state.StateDB, address common.Address, slot common.Hash, limit int) ([]byte, error) {
	word := st.GetState(address, slot)
	if word[31]&1 == 0 {
		n := int(word[31] / 2)
		if n > 31 || n > limit {
			return nil, ErrInput
		}
		return append([]byte{}, word[:n]...), nil
	}
	length := new(big.Int).Rsh(word.Big(), 1)
	if !length.IsUint64() || length.Uint64() < 32 || length.Uint64() > uint64(limit) {
		return nil, ErrInput
	}
	n := int(length.Uint64())
	start := crypto.Keccak256Hash(slot[:])
	out := make([]byte, 0, n)
	for i := 0; len(out) < n; i++ {
		if ctx.Err() != nil {
			return nil, ErrInput
		}
		value := st.GetState(address, offsetSlot(start, uint64(i)))
		out = append(out, value[:min(32, n-len(out))]...)
	}
	if st.Error() != nil {
		return nil, ErrInput
	}
	return out, nil
}

func readRegistry(ctx context.Context, st *state.StateDB, address common.Address, deleteEmpty bool) (*RegistryState, error) {
	if ctx.Err() != nil || address == (common.Address{}) || st.GetCodeHash(address) != validatorProfile.code {
		return nil, ErrInput
	}
	length := st.GetState(address, stateSlot(0x33)).Big()
	if !length.IsUint64() || length.Uint64() > maxRegistryCandidates {
		return nil, ErrInput
	}
	out := &RegistryState{Layout: registryLayout, Address: strings.ToLower(address.Hex()), CodeHash: validatorProfile.code.Hex(), Candidates: []RegistryCandidate{}, WithoutKeys: []string{}}
	start := stateSlot(0x33)
	start = crypto.Keccak256Hash(start[:])
	seen := make(map[common.Address]bool)
	for i := uint64(0); i < length.Uint64(); i++ {
		if ctx.Err() != nil {
			return nil, ErrInput
		}
		candidate, err := storedAddress(st.GetState(address, offsetSlot(start, i)))
		if err != nil || candidate == (common.Address{}) || seen[candidate] {
			return nil, ErrInput
		}
		seen[candidate] = true
		if st.GetState(address, addressSlot(candidate, 0x34)) != stateSlot(i+1) {
			return nil, ErrInput
		}
		operator, err := storedAddress(st.GetState(address, addressSlot(candidate, 0x35)))
		if err != nil {
			return nil, ErrInput
		}
		if operator != (common.Address{}) && st.GetState(address, addressSlot(operator, 0x36)) != common.BytesToHash(candidate[:]) {
			return nil, ErrInput
		}
		head := addressSlot(candidate, 0x37)
		encoded := st.GetState(address, head)
		if encoded != (common.Hash{}) && encoded != stateSlot(97) {
			return nil, ErrInput
		}
		key, err := readStoredBytes(ctx, st, address, head, 48)
		if err != nil {
			return nil, err
		}
		if len(key) != 0 {
			point := new(blst.P1Affine).Uncompress(key)
			if len(key) != 48 || point == nil || !point.KeyValidate() || !bytes.Equal(point.Compress(), key) {
				return nil, ErrInput
			}
			base := stateSlot(0x38)
			if st.GetState(address, crypto.Keccak256Hash(key, base[:])) != common.BytesToHash(candidate[:]) {
				return nil, ErrInput
			}
		} else {
			out.WithoutKeys = append(out.WithoutKeys, strings.ToLower(candidate.Hex()))
		}
		out.Candidates = append(out.Candidates, RegistryCandidate{Address: strings.ToLower(candidate.Hex()), Operator: strings.ToLower(operator.Hex()), Key: digest(key)})
	}
	accounts, err := storageAccounts(st, []common.Address{address}, deleteEmpty)
	if err != nil {
		return nil, err
	}
	out.StorageRoot = accounts[0].root.Hex()
	return out, nil
}

func registryRead(ctx context.Context, st *state.StateDB, sc params.SystemContracts, deleteEmpty bool) RegistryRead {
	if sc.GovValidator == nil || sc.GovValidator.Address == (common.Address{}) {
		return RegistryRead{Status: "unavailable", Reason: "unconfigured_authority"}
	}
	if sc.GovCouncil != nil && sc.GovCouncil.Address == sc.GovValidator.Address {
		return RegistryRead{Status: "unavailable", Reason: "ambiguous_authority"}
	}
	if sc.GovValidator.Version != "v1" || st.GetCodeHash(sc.GovValidator.Address) != validatorProfile.code {
		return RegistryRead{Status: "unavailable", Reason: "unsupported_runtime"}
	}
	result, err := readRegistry(ctx, st, sc.GovValidator.Address, deleteEmpty)
	if err != nil {
		return RegistryRead{Status: "unavailable", Reason: "inconsistent_registry"}
	}
	return RegistryRead{Status: "observed", Reason: "reviewed_runtime", State: result}
}

func readProposal(ctx context.Context, st *state.StateDB, address common.Address, profile common.Hash, id *big.Int) (*ProposalState, error) {
	if id == nil || id.Sign() < 0 || id.BitLen() > 256 || st.GetCodeHash(address) != profile || ctx.Err() != nil {
		return nil, ErrInput
	}
	base := mapSlot(common.BigToHash(id), 7)
	get := func(n uint64) common.Hash { return st.GetState(address, offsetSlot(base, n)) }
	action, version, created, executed, packed, status := get(0), get(1), get(3), get(4), get(5), get(6)
	if status.Big().BitLen() > 8 || status[31] > 7 {
		return nil, ErrInput
	}
	data, err := readStoredBytes(ctx, st, address, offsetSlot(base, 7), MaxSourceBytes)
	if err != nil || st.Error() != nil {
		return nil, ErrInput
	}
	return &ProposalState{ID: id.String(), Status: strconv.FormatUint(uint64(status[31]), 10), Action: action.Hex(), CallData: digest(data), MemberVersion: version.Big().String(), CreatedAt: created.Big().String(), ExecutedAt: executed.Big().String(), Proposer: strings.ToLower(common.BytesToAddress(packed[12:]).Hex()), RequiredApprovals: binary.BigEndian.Uint32(packed[8:12]), Approved: binary.BigEndian.Uint32(packed[4:8]), Rejected: binary.BigEndian.Uint32(packed[:4]), ExecutionCount: st.GetState(address, mapSlot(common.BigToHash(id), 10)).Big().String()}, nil
}
