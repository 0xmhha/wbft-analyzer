package executionwitness

import (
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

func epochLineageFixture() (TransitionReport, *types.EpochInfo) {
	report, source, _ := transitionFixture()
	slots := registryEffectSlots(report.Transactions[0].Effects[0], report.Transactions[0].RegistryBefore, report.Transactions[0].RegistryAfter)
	// Only the membership-position mapping is changed in this synthetic origin.
	var input [64]byte
	for i := 12; i < 32; i++ {
		input[i] = 0x22
	}
	input[63] = 0x34
	slot := keccak.Sum256(input[:])
	report.Transactions[0].Writes[0].SlotSHA256 = digest(slot[:]).SHA256
	if !slots[report.Transactions[0].Writes[0].SlotSHA256] {
		panic("membership slot missing from registry dependencies")
	}
	return report, source.epochs["2"]
}

func addUnchangedRegistryTransaction(report *TransitionReport) {
	origin := report.Transactions[0]
	point := origin
	point.Ordinal = len(report.Transactions)
	point.Hash = "0x" + strings.Repeat(string(rune('b'+point.Ordinal)), 64)
	point.AccountsBefore = origin.AccountsAfter
	point.AccountsAfter = origin.AccountsAfter
	point.RegistryBefore = origin.RegistryAfter
	point.RegistryAfter = origin.RegistryAfter
	point.Writes = []StorageWrite{}
	point.Effects = []RegistryEffect{}
	point.CauseStatus, point.Reason = "unestablished", "no_registry_change"
	transaction := report.Execution.Transactions[0]
	transaction.Ordinal, transaction.Hash = point.Ordinal, point.Hash
	report.Transactions = append(report.Transactions, point)
	report.Execution.Transactions = append(report.Execution.Transactions, transaction)
}

func TestEpochLineageRetainsCompleteEffectWithoutSelectingValidators(t *testing.T) {
	report, epoch := epochLineageFixture()
	before := cloneTransitions(t, report)
	got := TrackEpochEffect(report, 0, 0, "2", epoch)
	if got.Status != "verified_retained_registry_effect" || got.CheckedBlocks != 2 || got.CheckedTransactions != 1 || got.TransactionIndex != "1" || got.EpochIndex != "2" {
		t.Fatal("complete retained registry effect not linked", got)
	}
	if !reflect.DeepEqual(before, report) {
		t.Fatal("lineage read mutated evidence")
	}
	addUnchangedRegistryTransaction(&report)
	if got = TrackEpochEffect(report, 0, 0, "2", epoch); got.Status != "verified_retained_registry_effect" || got.CheckedTransactions != 2 {
		t.Fatal("unrelated later transaction erased retention", got)
	}
}

func TestEpochLineageRejectsIncompleteOrChangedPaths(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*TransitionReport, *types.EpochInfo)
	}{
		{"missing block", func(r *TransitionReport, _ *types.EpochInfo) { r.Blocks = r.Blocks[:2] }},
		{"duplicate block", func(r *TransitionReport, _ *types.EpochInfo) { r.Blocks[2].Index = "1" }},
		{"out of order block", func(r *TransitionReport, _ *types.EpochInfo) { r.Blocks[1], r.Blocks[2] = r.Blocks[2], r.Blocks[1] }},
		{"missing transaction", func(r *TransitionReport, _ *types.EpochInfo) { r.Transactions = nil }},
		{"different legacy hash", func(r *TransitionReport, _ *types.EpochInfo) { r.Execution.Transactions[0].Hash = "different" }},
		{"different block hash", func(r *TransitionReport, _ *types.EpochInfo) { r.Execution.Source.Blocks[1].Hash = "different" }},
		{"missing phase", func(r *TransitionReport, _ *types.EpochInfo) { r.Blocks[2].BeforeSystem = nil }},
		{"changed boundary", func(r *TransitionReport, _ *types.EpochInfo) {
			r.Blocks[2].BeforeSystem[0].StorageRoot = "0x" + strings.Repeat("d", 64)
		}},
		{"system processing changed registry", func(r *TransitionReport, _ *types.EpochInfo) {
			account := r.Blocks[2].BeforeTransactions[0]
			account.StorageRoot = "0x" + strings.Repeat("d", 64)
			r.Blocks[2].BeforeTransactions = []ContractStorage{account}
			r.Blocks[2].AfterTransactions = []ContractStorage{account}
		}},
		{"registry code changed", func(r *TransitionReport, _ *types.EpochInfo) {
			r.Blocks[2].Finalized[0].CodeHash = "0x" + strings.Repeat("d", 64)
		}},
		{"registry lifecycle changed", func(r *TransitionReport, _ *types.EpochInfo) { r.Blocks[2].Finalized[0].Exists = false }},
		{"missing epoch", func(r *TransitionReport, _ *types.EpochInfo) { r.Blocks[2].EpochRegistry = nil }},
		{"earlier epoch", func(r *TransitionReport, _ *types.EpochInfo) { r.Blocks[1].EpochRegistry = r.Blocks[2].EpochRegistry }},
		{"unavailable epoch state", func(r *TransitionReport, _ *types.EpochInfo) {
			r.Blocks[2].EpochRegistry = &RegistryRead{Status: "unavailable", Reason: "inconsistent_registry"}
		}},
		{"wrong epoch candidate", func(_ *TransitionReport, e *types.EpochInfo) { e.Candidates[0].Addr[0] ^= 1 }},
		{"wrong selected key", func(_ *TransitionReport, e *types.EpochInfo) { e.BLSPublicKeys[0][0] ^= 1 }},
		{"nested origin", func(r *TransitionReport, _ *types.EpochInfo) {
			r.Execution.Transactions[0].Frames[0].Kind = "DELEGATECALL"
		}},
		{"unverified origin", func(r *TransitionReport, _ *types.EpochInfo) {
			r.Transactions[0].CauseStatus, r.Transactions[0].Reason = "unestablished", "unmapped_execution"
		}},
		{"later missing registry", func(r *TransitionReport, _ *types.EpochInfo) {
			addUnchangedRegistryTransaction(r)
			p := &r.Transactions[1]
			p.RegistryBefore = RegistryRead{Status: "unavailable", Reason: "inconsistent_registry"}
			p.RegistryAfter = p.RegistryBefore
			p.Reason = "unavailable_registry_state"
		}},
		{"later ordinal gap", func(r *TransitionReport, _ *types.EpochInfo) {
			addUnchangedRegistryTransaction(r)
			r.Transactions[1].Ordinal = 2
			r.Execution.Transactions[1].Ordinal = 2
		}},
		{"later duplicated ordinal", func(r *TransitionReport, _ *types.EpochInfo) {
			addUnchangedRegistryTransaction(r)
			r.Transactions[1].Ordinal = 0
			r.Execution.Transactions[1].Ordinal = 0
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, epoch := epochLineageFixture()
			report = cloneTransitions(t, report)
			test.mutate(&report, epoch)
			if got := TrackEpochEffect(report, 0, 0, "2", epoch); got.Status != "unverified" {
				t.Fatal("incomplete or changed path became causal", got)
			}
		})
	}
}

func TestEpochLineageDistinguishesRetainedAndRevertedOverwrite(t *testing.T) {
	for _, reverted := range []bool{false, true} {
		report, epoch := epochLineageFixture()
		addUnchangedRegistryTransaction(&report)
		write := report.Transactions[0].Writes[0]
		write.Before = write.After
		write.Reverted = reverted
		if reverted {
			frame := report.Execution.Transactions[1].Frames[0]
			frame.Path, frame.Effective, frame.Status = []uint32{0}, false, "reverted"
			report.Execution.Transactions[1].Frames = append(report.Execution.Transactions[1].Frames, frame)
			write.Frame, write.Path = 1, []uint32{0}
		}
		report.Transactions[1].Writes = []StorageWrite{write}
		got := TrackEpochEffect(report, 0, 0, "2", epoch)
		if reverted {
			if got.Status != "verified_retained_registry_effect" {
				t.Fatal("reverted child write erased retained effect", got)
			}
		} else if got.Status != "unverified" || got.Reason != "retained_write_overwritten" {
			t.Fatal("idempotent later write borrowed exclusive attribution", got)
		}
	}
}

func TestEpochLineageIgnoresProposalCounterOverwrite(t *testing.T) {
	report, epoch := epochLineageFixture()
	var counterInput [64]byte
	for i := 12; i < 32; i++ {
		counterInput[i] = 0x22
	}
	counterInput[63] = 11 // Reviewed member-active-proposal-count mapping.
	counter := keccak.Sum256(counterInput[:])
	write := report.Transactions[0].Writes[0]
	write.SlotSHA256 = digest(counter[:]).SHA256
	report.Transactions[0].Writes = append(report.Transactions[0].Writes, write)
	addUnchangedRegistryTransaction(&report)
	later := &report.Transactions[1]
	write.Before = write.After
	word := lineageSlot(2)
	write.After = digest(word[:])
	later.Writes = []StorageWrite{write}
	state := *later.RegistryAfter.State
	state.StorageRoot = "0x" + strings.Repeat("d", 64)
	later.RegistryAfter.State = &state
	account := later.AccountsAfter[0]
	account.StorageRoot = state.StorageRoot
	later.AccountsAfter = []ContractStorage{account}
	report.Blocks[1].AfterTransactions, report.Blocks[1].Finalized = later.AccountsAfter, later.AccountsAfter
	report.Blocks[2].BeforeSystem, report.Blocks[2].BeforeTransactions = later.AccountsAfter, later.AccountsAfter
	report.Blocks[2].AfterTransactions, report.Blocks[2].Finalized = later.AccountsAfter, later.AccountsAfter
	report.Blocks[2].EpochRegistry = &later.RegistryAfter
	if got := TrackEpochEffect(report, 0, 0, "2", epoch); got.Status != "verified_retained_registry_effect" {
		t.Fatal("unrelated proposal counter overwrite erased candidate retention", got)
	}
}

func TestRegistrySlotOffsetCarriesAndWraps(t *testing.T) {
	var largest [32]byte
	for i := range largest {
		largest[i] = 255
	}
	if got := lineageSlotOffset(largest, 1); got != ([32]byte{}) {
		t.Fatal("EVM slot arithmetic did not wrap")
	}
	if got := lineageSlotOffset(lineageSlot(255), 257); got != lineageSlot(512) {
		t.Fatal("EVM slot arithmetic lost carry")
	}
}

func TestEpochLineageRejectsUndoAndReadditionWithSameFinalState(t *testing.T) {
	report, epoch := epochLineageFixture()
	addUnchangedRegistryTransaction(&report)
	addUnchangedRegistryTransaction(&report)
	removed := report.Transactions[0].RegistryBefore
	state := *removed.State
	state.StorageRoot = "0x" + strings.Repeat("d", 64)
	removed.State = &state
	account := report.Transactions[0].AccountsBefore[0]
	account.StorageRoot = state.StorageRoot
	p := &report.Transactions[1]
	p.RegistryAfter = removed
	p.AccountsAfter = []ContractStorage{account}
	p.Effects = expectedRegistryEffects(p.RegistryBefore, p.RegistryAfter)
	p.Writes = append([]StorageWrite{}, report.Transactions[0].Writes...)
	p.Writes[0].Before, p.Writes[0].After = p.Writes[0].After, p.Writes[0].Before
	p.Reason, p.CauseStatus = "reviewed_runtime_writes", "verified_transaction_effect"
	p = &report.Transactions[2]
	p.RegistryBefore = removed
	p.AccountsBefore = []ContractStorage{account}
	p.Effects = expectedRegistryEffects(p.RegistryBefore, p.RegistryAfter)
	p.Writes = append([]StorageWrite{}, report.Transactions[0].Writes...)
	p.Reason, p.CauseStatus = "reviewed_runtime_writes", "verified_transaction_effect"
	for i, point := range report.Transactions {
		if !validTransitionPoint(point, report.Execution.Transactions[i], report.Blocks[1]) {
			t.Fatal("undo/readdition fixture does not describe a complete transition", i)
		}
	}
	if got := TrackEpochEffect(report, 0, 0, "2", epoch); got.Status != "unverified" || got.Reason != "effect_not_retained" {
		t.Fatal("same final state concealed an intervening removal", got)
	}
}

func TestEpochLineageCoversRegistryEffectKindsAndUnselectedNoKey(t *testing.T) {
	for _, kind := range []string{"candidate_added", "candidate_removed", "candidate_key_changed", "operator_changed", "candidate_updated", "candidate_order_changed", "unselected_no_key"} {
		t.Run(kind, func(t *testing.T) {
			report, epoch := epochLineageFixture()
			point := &report.Transactions[0]
			before, after := *point.RegistryBefore.State, *point.RegistryAfter.State
			candidate := after.Candidates[0]
			baseline := candidate
			baseline.Address = "0x" + strings.Repeat("3", 40)
			baseKey := []byte(strings.Repeat("b", 48))
			baseline.Key = digest(baseKey)
			var baselineAddress types.Address
			for i := range baselineAddress {
				baselineAddress[i] = 0x33
			}
			switch kind {
			case "candidate_added":
				// The original fixture already represents a retained addition.
			case "candidate_removed":
				before.Candidates = []RegistryCandidate{candidate, baseline}
				after.Candidates = []RegistryCandidate{baseline}
				epoch.Candidates = []types.Candidate{{Addr: baselineAddress}}
				epoch.BLSPublicKeys = [][]byte{baseKey}
			case "candidate_key_changed", "operator_changed", "candidate_updated":
				old := candidate
				if kind != "operator_changed" {
					old.Key = digest([]byte(strings.Repeat("x", 48)))
				}
				if kind != "candidate_key_changed" {
					old.Operator = baseline.Address
				}
				before.Candidates = []RegistryCandidate{old}
			case "candidate_order_changed":
				before.Candidates = []RegistryCandidate{candidate, baseline}
				after.Candidates = []RegistryCandidate{baseline, candidate}
				epoch.Candidates = append([]types.Candidate{{Addr: baselineAddress}}, epoch.Candidates...)
				epoch.BLSPublicKeys = [][]byte{baseKey}
			case "unselected_no_key":
				candidate.Key = digest(nil)
				before.Candidates = []RegistryCandidate{baseline}
				after.Candidates = []RegistryCandidate{baseline, candidate}
				after.WithoutKeys = []string{candidate.Address}
				epoch.Candidates = append([]types.Candidate{{Addr: baselineAddress}}, epoch.Candidates...)
				epoch.BLSPublicKeys = [][]byte{baseKey}
			}
			point.RegistryBefore.State, point.RegistryAfter.State = &before, &after
			point.Effects = expectedRegistryEffects(point.RegistryBefore, point.RegistryAfter)
			dependencies := registryEffectSlots(point.Effects[0], point.RegistryBefore, point.RegistryAfter)
			for slot := range dependencies {
				point.Writes[0].SlotSHA256 = slot
				break
			}
			report.Blocks[2].EpochRegistry = &point.RegistryAfter
			if !validTransitionPoint(*point, report.Execution.Transactions[0], report.Blocks[1]) || len(point.Effects) != 1 {
				t.Fatal("invalid registry effect fixture", kind)
			}
			if kind != "unselected_no_key" && point.Effects[0].Kind != kind {
				t.Fatal("wrong effect fixture", point.Effects)
			}
			if got := TrackEpochEffect(report, 0, 0, "2", epoch); got.Status != "verified_retained_registry_effect" {
				t.Fatal("retained registry effect not recognized", kind, got)
			}
		})
	}
}

func TestEpochLineageRejectsInvalidSelectorsAndScope(t *testing.T) {
	report, epoch := epochLineageFixture()
	for _, scope := range []struct {
		point, effect int
		epoch         string
	}{{-1, 0, "2"}, {1, 0, "2"}, {0, -1, "2"}, {0, 1, "2"}, {0, 0, "02"}, {0, 0, "0"}, {0, 0, "18446744073709551616"}} {
		if got := TrackEpochEffect(report, scope.point, scope.effect, scope.epoch, epoch); got.Status != "unverified" {
			t.Fatal("invalid scope became verified", scope, got)
		}
	}
	if got := TrackEpochEffect(report, 0, 0, "2", nil); got.Status != "unverified" {
		t.Fatal("missing epoch header became verified", got)
	}
}
