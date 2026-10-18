package executionwitness

import (
	"reflect"
	"strconv"

	"github.com/0xmhha/wbft/types"
)

// EpochEffectLineage describes retention of a transaction's complete registry
// effect. It never attributes validator selection or diligence to a transaction.
type EpochEffectLineage struct {
	Status              string `json:"status" enum:"unverified,verified_retained_registry_effect"`
	Reason              string `json:"reason" enum:"invalid_scope,origin_effect_unverified,next_epoch_unavailable,epoch_header_mismatch,registry_state_unavailable,registry_boundary_mismatch,system_phase_changed,effect_not_retained,retained_write_overwritten,verified_retained_registry_effect"`
	TransactionIndex    string `json:"transaction_index"`
	EpochIndex          string `json:"epoch_index"`
	CheckedBlocks       int    `json:"checked_blocks"`
	CheckedTransactions int    `json:"checked_transactions"`
}

// EpochRegistryMatches compares reviewed registry state with the ordered epoch
// candidates and selected keys. It does not explain selection or authenticate a
// caller-supplied report; readers must retain their original source binding.
func EpochRegistryMatches(info *types.EpochInfo, read RegistryRead) bool {
	return validRegistryRead(read) && epochRegistryMatches(info, read)
}

// TrackEpochEffect derives a bounded comparison from an already admitted full
// transition report. This is not an admission or header authentication API. A
// consumer must also revalidate the original canonical/configuration dependency
// and the matching governance operation before presenting verified evidence.
func TrackEpochEffect(report TransitionReport, point, effect int, epochIndex string, epoch *types.EpochInfo) EpochEffectLineage {
	result := EpochEffectLineage{Status: "unverified", Reason: "invalid_scope", EpochIndex: epochIndex}
	epochNumber, err := strconv.ParseUint(epochIndex, 10, 64)
	if err != nil || strconv.FormatUint(epochNumber, 10) != epochIndex || epochNumber == 0 || len(report.Blocks) == 0 || len(report.Blocks) > MaxBlocks || len(report.Blocks) != len(report.Execution.Source.Blocks) || len(report.Transactions) != len(report.Execution.Transactions) || len(report.Transactions) > MaxTransactions || report.Protocol != TransitionProtocol || report.Execution.Protocol != Protocol || point < 0 || point >= len(report.Transactions) || epochNumber >= uint64(len(report.Blocks)) {
		return result
	}
	origin := report.Transactions[point]
	result.TransactionIndex = origin.Index
	first, err := strconv.ParseUint(origin.Index, 10, 64)
	if err != nil || first == 0 || first > epochNumber || effect < 0 || effect >= len(origin.Effects) {
		return result
	}
	byBlock := make([][]int, len(report.Blocks))
	for i, block := range report.Blocks {
		index := strconv.Itoa(i)
		if block.Index != index || report.Execution.Source.Blocks[i].Index != index || block.Genesis != (i == 0) {
			return result
		}
	}
	previous, writes := uint64(0), 0
	for i, transaction := range report.Transactions {
		index, e := strconv.ParseUint(transaction.Index, 10, 64)
		if e != nil || index == 0 || index >= uint64(len(report.Blocks)) || index < previous || transaction.Ordinal != len(byBlock[index]) || transaction.BlockHash != report.Execution.Source.Blocks[index].Hash {
			return result
		}
		writes += len(transaction.Writes)
		if writes > 100000 || !validTransitionPoint(transaction, report.Execution.Transactions[i], report.Blocks[index]) {
			return result
		}
		byBlock[index] = append(byBlock[index], i)
		previous = index
	}
	result.Reason = "origin_effect_unverified"
	if origin.CauseStatus != "verified_transaction_effect" || origin.RegistryAfter.State == nil {
		return result
	}
	owner := origin.RegistryAfter.State.Address
	wanted := origin.Effects[effect]
	protected := retainedRegistrySlots(origin, owner, registryEffectSlots(wanted, origin.RegistryBefore, origin.RegistryAfter))
	if len(protected) == 0 {
		return result
	}
	result.Reason = "next_epoch_unavailable"
	for i := first; i <= epochNumber; i++ {
		if report.Blocks[i].EpochRegistry != nil && i != epochNumber {
			return result
		}
	}
	last := report.Blocks[epochNumber]
	if last.EpochRegistry == nil {
		return result
	}
	result.Reason = "epoch_header_mismatch"
	if !validRegistryRead(*last.EpochRegistry) || !epochRegistryMatches(epoch, *last.EpochRegistry) {
		return result
	}
	if !registryRetainsEffect(wanted, origin.RegistryAfter, *last.EpochRegistry) {
		result.Reason = "effect_not_retained"
		return result
	}
	var previousFinal ContractStorage
	for index := first; index <= epochNumber; index++ {
		block := report.Blocks[index]
		before, ok := lineageAccount(block.BeforeSystem, owner)
		start, startOK := lineageAccount(block.BeforeTransactions, owner)
		end, endOK := lineageAccount(block.AfterTransactions, owner)
		final, finalOK := lineageAccount(block.Finalized, owner)
		result.Reason = "registry_boundary_mismatch"
		if !ok || !startOK || !endOK || !finalOK || before.CodeHash != origin.RegistryAfter.State.CodeHash || !before.Exists || index > first && before != previousFinal {
			return result
		}
		result.Reason = "system_phase_changed"
		if before != start || end != final {
			return result
		}
		current := start
		for _, ordinal := range byBlock[index] {
			transaction := report.Transactions[ordinal]
			a, beforeOK := lineageAccount(transaction.AccountsBefore, owner)
			b, afterOK := lineageAccount(transaction.AccountsAfter, owner)
			result.Reason = "registry_boundary_mismatch"
			if !beforeOK || !afterOK || a != current || a.Address != b.Address || a.CodeHash != b.CodeHash || !b.Exists {
				return result
			}
			current = b
			if ordinal < point {
				continue
			}
			result.CheckedTransactions++
			if ordinal == point {
				continue
			}
			result.Reason = "registry_state_unavailable"
			if transaction.RegistryBefore.State == nil || transaction.RegistryAfter.State == nil || transaction.RegistryBefore.State.Address != owner || transaction.RegistryAfter.State.Address != owner {
				return result
			}
			result.Reason = "effect_not_retained"
			if !registryRetainsEffect(wanted, origin.RegistryAfter, transaction.RegistryBefore) || !registryRetainsEffect(wanted, origin.RegistryAfter, transaction.RegistryAfter) {
				return result
			}
			result.Reason = "retained_write_overwritten"
			for _, write := range transaction.Writes {
				if !write.Reverted && write.Address == owner && protected[write.SlotSHA256] {
					return result
				}
			}
		}
		result.Reason = "registry_boundary_mismatch"
		if current != end {
			return result
		}
		previousFinal = final
		result.CheckedBlocks++
	}
	result.Reason = "registry_boundary_mismatch"
	if last.EpochRegistry.State == nil || last.EpochRegistry.State.StorageRoot != previousFinal.StorageRoot || last.EpochRegistry.State.Address != owner || last.EpochRegistry.State.CodeHash != previousFinal.CodeHash {
		return result
	}
	result.Status, result.Reason = "verified_retained_registry_effect", "verified_retained_registry_effect"
	return result
}

func lineageAccount(accounts []ContractStorage, owner string) (ContractStorage, bool) {
	all, ok := storageAccountMap(accounts)
	if !ok {
		return ContractStorage{}, false
	}
	account, found := all[owner]
	return account, found
}

func retainedRegistrySlots(point TransactionTransition, owner string, dependencies map[string]bool) map[string]bool {
	first, last := map[string]Digest{}, map[string]Digest{}
	for _, write := range point.Writes {
		if write.Reverted || write.Address != owner || !dependencies[write.SlotSHA256] {
			continue
		}
		if _, found := first[write.SlotSHA256]; !found {
			first[write.SlotSHA256] = write.Before
		}
		last[write.SlotSHA256] = write.After
	}
	out := map[string]bool{}
	for slot, before := range first {
		if before != last[slot] {
			out[slot] = true
		}
	}
	return out
}

func registryRetainsEffect(effect RegistryEffect, after, current RegistryRead) bool {
	if after.Status != "observed" || current.Status != "observed" || after.State == nil || current.State == nil || after.State.Address != current.State.Address || after.State.CodeHash != current.State.CodeHash {
		return false
	}
	if effect.Kind == "candidate_order_changed" {
		if len(after.State.Candidates) != len(current.State.Candidates) {
			return false
		}
		for i, candidate := range after.State.Candidates {
			if candidate.Address != current.State.Candidates[i].Address {
				return false
			}
		}
		return true
	}
	for _, candidate := range current.State.Candidates {
		if candidate.Address == effect.Candidate {
			return effect.After != nil && reflect.DeepEqual(*effect.After, candidate)
		}
	}
	return effect.Kind == "candidate_removed" && effect.After == nil && effect.Before != nil
}
