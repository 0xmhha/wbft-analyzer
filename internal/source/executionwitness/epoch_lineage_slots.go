package executionwitness

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/0xmhha/wbft/crypto/keccak"
)

// These dependencies use only the reviewed validator-registry layout. Proposal
// counters and other contract storage do not establish candidate retention.
// Raw slot keys stay local; comparisons use the existing write-slot digests.
func registryEffectSlots(effect RegistryEffect, before, after RegistryRead) map[string]bool {
	out := map[string]bool{}
	add := func(slot [32]byte) { out[digest(slot[:]).SHA256] = true }
	if before.State == nil || after.State == nil || before.State.Layout != registryLayout || after.State.Layout != registryLayout || before.State.CodeHash != validatorCodeHash || after.State.CodeHash != validatorCodeHash {
		return out
	}
	if effect.Kind == "candidate_order_changed" {
		if len(before.State.Candidates) != len(after.State.Candidates) {
			return out
		}
		length := lineageSlot(0x33)
		start := [32]byte(keccak.Sum256(length[:]))
		for i, candidate := range before.State.Candidates {
			if candidate.Address != after.State.Candidates[i].Address {
				add(lineageSlotOffset(start, uint64(i)))
			}
		}
		return out
	}
	address, err := hex.DecodeString(trimHex(effect.Candidate))
	if err != nil || len(address) != 20 {
		return out
	}
	mapping := func(number uint64) [32]byte {
		var input [64]byte
		copy(input[12:32], address)
		binary.BigEndian.PutUint64(input[56:], number)
		return [32]byte(keccak.Sum256(input[:]))
	}
	switch effect.Kind {
	case "candidate_removed":
		add(mapping(0x34))
	case "operator_changed":
		add(mapping(0x35))
	case "candidate_added", "candidate_updated", "candidate_key_changed":
		if effect.Kind == "candidate_added" {
			add(mapping(0x34))
		}
		if effect.Kind != "candidate_key_changed" {
			add(mapping(0x35))
		}
		head := mapping(0x37)
		add(head)
		data := [32]byte(keccak.Sum256(head[:]))
		add(data)
		add(lineageSlotOffset(data, 1))
	}
	return out
}

func lineageSlot(number uint64) (slot [32]byte) {
	binary.BigEndian.PutUint64(slot[24:], number)
	return slot
}

func lineageSlotOffset(slot [32]byte, offset uint64) [32]byte {
	// EVM storage addresses wrap modulo 2^256.
	for i := len(slot) - 1; i >= 0 && offset != 0; i-- {
		value := uint64(slot[i]) + (offset & 255)
		slot[i] = byte(value)
		offset = (offset >> 8) + (value >> 8)
	}
	return slot
}

func trimHex(value string) string {
	if len(value) >= 2 && value[:2] == "0x" {
		return value[2:]
	}
	return value
}
