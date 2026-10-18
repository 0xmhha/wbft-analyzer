package executionwitness

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

type TransitionProjection struct {
	Report   TransitionReport `json:"report"`
	Verifier Verifier         `json:"verifier"`
}

// TransitionBundle is admitted only through original replay with an explicit
// operator-selected implementation. A JSON report cannot construct a bundle.
type TransitionBundle struct{ value TransitionProjection }

func (*TransitionBundle) UnmarshalJSON([]byte) error { return ErrSource }
func (b TransitionBundle) Projection() TransitionProjection {
	raw, _ := json.Marshal(b.value)
	var copy TransitionProjection
	_ = json.Unmarshal(raw, &copy)
	return copy
}

// LoadTransitions admits governance storage observations only after complete
// original replay and source binding. Neither JSON input chooses the helper mode.
func LoadTransitions(ctx context.Context, raw []byte, root *os.Root, h Helper) (TransitionBundle, error) {
	var projection TransitionProjection
	err := loadHelper(ctx, raw, root, h, true, func(output []byte, source snapshot, origin Origin) error {
		report, err := decodeTransitions(output, source, origin)
		if err != nil {
			return err
		}
		projection = TransitionProjection{Report: report, Verifier: Verifier{SHA256: h.SHA256, Origin: origin}}
		return nil
	})
	if err != nil {
		return TransitionBundle{}, err
	}
	return TransitionBundle{value: projection}, nil
}

func decodeTransitions(output []byte, source snapshot, origin Origin) (TransitionReport, error) {
	var report TransitionReport
	if !utf8.Valid(output) || jsonmeta.Decode(output, MaxProjectionBytes, true, &report) != nil || !requiredFields(output, reflect.TypeOf(report)) || validateTransitions(report, source, origin) != nil {
		return TransitionReport{}, ErrSource
	}
	return report, nil
}

// Every wire field is present. Only pointer fields admit explicit null;
// missing false-valued fields must not silently become an assertion.
func requiredFields(raw json.RawMessage, typ reflect.Type) bool {
	if typ.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return true
		}
		return requiredFields(raw, typ.Elem())
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil || len(fields) != typ.NumField() {
			return false
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			value, exists := fields[name]
			if !exists || !requiredFields(value, field.Type) {
				return false
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return false
		}
		for _, value := range values {
			if !requiredFields(value, typ.Elem()) {
				return false
			}
		}
	}
	return true
}

func storageAccountMap(accounts []ContractStorage) (map[string]ContractStorage, bool) {
	if accounts == nil || len(accounts) > 16 {
		return nil, false
	}
	out := make(map[string]ContractStorage)
	previous := ""
	for _, account := range accounts {
		if !wireHex(account.Address, 20) || account.Address <= previous || account.Address == "0x"+strings.Repeat("0", 40) || !wireHex(account.CodeHash, 32) || !wireHex(account.StorageRoot, 32) {
			return nil, false
		}
		if !account.Exists && (account.CodeHash != "0x"+strings.Repeat("0", 64) || account.StorageRoot != "0x"+strings.Repeat("0", 64)) {
			return nil, false
		}
		previous = account.Address
		out[account.Address] = account
	}
	return out, true
}

func validRegistryRead(read RegistryRead) bool {
	if read.Status == "unavailable" {
		return read.State == nil && member("unconfigured_authority ambiguous_authority unsupported_runtime inconsistent_registry", read.Reason)
	}
	if read.Status != "observed" || read.Reason != "reviewed_runtime" || read.State == nil {
		return false
	}
	st := read.State
	if st.Layout != registryLayout || !wireHex(st.Address, 20) || st.CodeHash != validatorCodeHash || !wireHex(st.StorageRoot, 32) || st.Candidates == nil || st.WithoutKeys == nil || len(st.Candidates) > 4096 {
		return false
	}
	seen := make(map[string]bool)
	empty := []string{}
	for _, candidate := range st.Candidates {
		if !wireHex(candidate.Address, 20) || candidate.Address == "0x"+strings.Repeat("0", 40) || seen[candidate.Address] || !wireHex(candidate.Operator, 20) || candidate.Operator == "0x"+strings.Repeat("0", 40) || !validDigest(candidate.Key) || candidate.Key.Bytes != 0 && candidate.Key.Bytes != 48 {
			return false
		}
		seen[candidate.Address] = true
		if candidate.Key.Bytes == 0 {
			empty = append(empty, candidate.Address)
		}
	}
	return reflect.DeepEqual(empty, st.WithoutKeys)
}

func registryMatchesAccount(read RegistryRead, accounts map[string]ContractStorage) bool {
	if read.State == nil {
		return true
	}
	account, found := accounts[read.State.Address]
	return found && account.Exists && account.CodeHash == read.State.CodeHash && account.StorageRoot == read.State.StorageRoot
}

func uint256(value string) bool {
	n, ok := new(big.Int).SetString(value, 10)
	return ok && n.Sign() >= 0 && n.BitLen() <= 256 && n.String() == value
}

func validProposal(proposal *ProposalState) bool {
	if proposal == nil {
		return true
	}
	return uint256(proposal.ID) && member("0 1 2 3 4 5 6 7", proposal.Status) && wireHex(proposal.Action, 32) && validDigest(proposal.CallData) && uint256(proposal.MemberVersion) && uint256(proposal.CreatedAt) && uint256(proposal.ExecutedAt) && wireHex(proposal.Proposer, 20) && uint256(proposal.ExecutionCount)
}

func transitionMethodSignature(name string) string {
	switch name {
	case "approveProposal", "disapproveProposal", "cancelProposal", "executeProposal", "executeWithFailure", "expireProposal", "proposeChangeMaxProposals", "proposeGasTip":
		return name + "(uint256)"
	case "changeMember", "proposeAddBlacklist", "proposeRemoveBlacklist", "proposeAddAuthorizedAccount", "proposeRemoveAuthorizedAccount":
		return name + "(address)"
	case "configureValidator":
		return name + "(address,bytes,bytes)"
	case "proposeAddMember", "proposeRemoveMember":
		return name + "(address,uint32)"
	case "proposeChangeQuorum":
		return name + "(uint32)"
	case "proposeAddBlacklistBatch", "proposeRemoveBlacklistBatch", "proposeAddAuthorizedAccountBatch", "proposeRemoveAuthorizedAccountBatch":
		return name + "(address[])"
	}
	return ""
}

func validTransitionMethod(method string, execution Transaction) bool {
	if method == "" {
		return true
	}
	signature := transitionMethodSignature(method)
	if signature == "" || len(execution.Frames) == 0 {
		return false
	}
	selector := keccak.Sum256Bytes([]byte(signature))
	if execution.Selector != "0x"+hex.EncodeToString(selector[:4]) {
		return false
	}
	root := execution.Frames[0]
	return root.Kind == "CALL" && (root.Authority == "gov_validator" && root.AccountCodeHash == validatorCodeHash || root.Authority == "gov_council" && root.AccountCodeHash == councilCodeHash)
}

func expectedRegistryEffects(before, after RegistryRead) []RegistryEffect {
	out := []RegistryEffect{}
	if before.State == nil || after.State == nil || before.Status != "observed" || after.Status != "observed" || before.State.Address != after.State.Address || before.State.CodeHash != after.State.CodeHash {
		return out
	}
	old, current := make(map[string]RegistryCandidate), make(map[string]RegistryCandidate)
	for _, v := range before.State.Candidates {
		old[v.Address] = v
	}
	for _, v := range after.State.Candidates {
		current[v.Address] = v
	}
	for _, v := range before.State.Candidates {
		previous := v
		next, exists := current[v.Address]
		if !exists {
			out = append(out, RegistryEffect{Kind: "candidate_removed", Candidate: v.Address, Before: &previous})
			continue
		}
		if previous.Key == next.Key && previous.Operator == next.Operator {
			continue
		}
		kind := "candidate_updated"
		if previous.Key == next.Key {
			kind = "operator_changed"
		} else if previous.Operator == next.Operator {
			kind = "candidate_key_changed"
		}
		out = append(out, RegistryEffect{Kind: kind, Candidate: v.Address, Before: &previous, After: &next})
	}
	for _, v := range after.State.Candidates {
		if _, exists := old[v.Address]; !exists {
			next := v
			out = append(out, RegistryEffect{Kind: "candidate_added", Candidate: v.Address, After: &next})
		}
	}
	if len(out) == 0 && !reflect.DeepEqual(before.State.Candidates, after.State.Candidates) {
		out = append(out, RegistryEffect{Kind: "candidate_order_changed"})
	}
	return out
}

func phaseTargetChanged(before, after []ContractStorage, address string) bool {
	var a, b *ContractStorage
	for i := range before {
		if before[i].Address == address {
			a = &before[i]
		}
	}
	for i := range after {
		if after[i].Address == address {
			b = &after[i]
		}
	}
	return a == nil || b == nil || *a != *b
}

func validTransitionPoint(point TransactionTransition, execution Transaction, block BlockTransition) bool {
	if point.Index != execution.Index || point.Ordinal != execution.Ordinal || point.Hash != execution.Hash || point.BlockHash != execution.BlockHash || point.Writes == nil || len(point.Writes) > 10000 || point.Effects == nil || !validRegistryRead(point.RegistryBefore) || !validRegistryRead(point.RegistryAfter) || !validProposal(point.ProposalBefore) || !validProposal(point.ProposalAfter) || !validTransitionMethod(point.Method, execution) {
		return false
	}
	before, ok := storageAccountMap(point.AccountsBefore)
	if !ok {
		return false
	}
	after, ok := storageAccountMap(point.AccountsAfter)
	if !ok || len(before) != len(after) {
		return false
	}
	for address, value := range before {
		other, found := after[address]
		if !found || value.CodeHash != other.CodeHash || value.Exists != other.Exists {
			return false
		}
	}
	if !registryMatchesAccount(point.RegistryBefore, before) || !registryMatchesAccount(point.RegistryAfter, after) {
		return false
	}
	if (point.ProposalBefore == nil) != (point.ProposalAfter == nil) || point.ProposalBefore != nil && (point.Method == "" || point.ProposalBefore.ID != point.ProposalAfter.ID) {
		return false
	}
	if !reflect.DeepEqual(expectedRegistryEffects(point.RegistryBefore, point.RegistryAfter), point.Effects) {
		return false
	}
	if len(point.Effects) > 0 && point.RegistryBefore.State.StorageRoot == point.RegistryAfter.State.StorageRoot {
		return false
	}
	if point.Status == "unavailable" {
		return point.Reason == "unconfigured_authority" && len(before) == 0 && len(point.Writes) == 0 && len(point.Effects) == 0 && point.Method == "" && point.RegistryBefore.Reason == "unconfigured_authority" && point.RegistryAfter.Reason == "unconfigured_authority" && point.RegistryBefore.State == nil && point.RegistryAfter.State == nil && point.ProposalBefore == nil && point.ProposalAfter == nil && point.CauseStatus == "unestablished"
	}
	if point.Status != "observed" || len(before) == 0 || !member("no_registry_change reverted_transaction unavailable_registry_state unmapped_execution reviewed_runtime_writes system_effects_overlap", point.Reason) {
		return false
	}
	fold := make(map[string]Digest)
	for _, write := range point.Writes {
		if _, found := before[write.Address]; !found {
			return false
		}
		if !hash(write.SlotSHA256, 32) || !validDigest(write.Before) || !validDigest(write.After) || write.Before.Bytes != 32 || write.After.Bytes != 32 || !wireHex(write.OwnerCodeHash, 32) || write.Frame < 0 || write.Frame >= len(execution.Frames) || write.Path == nil {
			return false
		}
		frame := execution.Frames[write.Frame]
		if !reflect.DeepEqual(write.Path, frame.Path) || !write.Reverted && !frame.Effective {
			return false
		}
		if write.Instruction != nil {
			pc, valid := number(write.Instruction.PC)
			if !valid || pc >= MaxSourceBytes || !wireHex(write.Instruction.CodeReference, 20) || !wireHex(write.Instruction.CodeHash, 32) {
				return false
			}
		} else if !write.Reverted {
			return false
		}
		if !write.Reverted {
			key := write.Address + write.SlotSHA256
			if previous, found := fold[key]; found && previous != write.Before {
				return false
			}
			fold[key] = write.After
		}
	}
	if point.Reason == "unavailable_registry_state" && point.RegistryBefore.Status == "observed" && point.RegistryAfter.Status == "observed" {
		return false
	}
	if point.Reason == "no_registry_change" && (len(point.Effects) != 0 || point.RegistryBefore.Status != "observed" || point.RegistryAfter.Status != "observed" || execution.ReceiptStatus != "succeeded") {
		return false
	}
	if point.Reason == "reverted_transaction" && (execution.ReceiptStatus != "failed" || len(point.Effects) != 0) {
		return false
	}
	if point.Reason == "unmapped_execution" && len(point.Effects) == 0 {
		return false
	}
	if point.Reason == "system_effects_overlap" {
		if point.RegistryAfter.State == nil {
			return false
		}
		address := point.RegistryAfter.State.Address
		if !phaseTargetChanged(block.BeforeSystem, block.BeforeTransactions, address) && !phaseTargetChanged(block.AfterTransactions, block.Finalized, address) {
			return false
		}
	}
	if point.CauseStatus == "unestablished" {
		return point.Reason != "reviewed_runtime_writes"
	}
	if point.CauseStatus != "verified_transaction_effect" || point.Reason != "reviewed_runtime_writes" || len(point.Effects) == 0 || point.Method == "" || execution.ReceiptStatus != "succeeded" || point.RegistryAfter.State == nil {
		return false
	}
	root := execution.Frames[0]
	address := point.RegistryAfter.State.Address
	if root.Kind != "CALL" || root.Authority != "gov_validator" || root.AccountCodeHash != validatorCodeHash || root.To != address || !root.Effective || phaseTargetChanged(block.BeforeSystem, block.BeforeTransactions, address) || phaseTargetChanged(block.AfterTransactions, block.Finalized, address) {
		return false
	}
	active := false
	for _, write := range point.Writes {
		if write.Reverted {
			continue
		}
		if write.Address != address || write.Frame != 0 || write.OwnerCodeHash != validatorCodeHash || write.Instruction == nil || write.Instruction.CodeReference != address || write.Instruction.CodeHash != validatorCodeHash {
			return false
		}
		pc, _ := number(write.Instruction.PC)
		if pc >= uint64(root.AccountCodeBytes) {
			return false
		}
		active = true
	}
	return active
}

// Epoch headers bind candidate ordering and selected public keys. Genesis is
// handled separately: its initial validator set can predate registry loading.
func epochRegistryMatches(info *types.EpochInfo, read RegistryRead) bool {
	if info == nil || read.State == nil || read.Status != "observed" {
		return false
	}
	candidates := read.State.Candidates
	if len(info.Candidates) == 0 || len(info.Candidates) != len(candidates) || len(info.Validators) == 0 || len(info.Validators) != len(info.BLSPublicKeys) {
		return false
	}
	for i, candidate := range info.Candidates {
		if strings.ToLower(candidate.Addr.Hex()) != candidates[i].Address {
			return false
		}
	}
	seen := make(map[uint32]bool)
	for i, index := range info.Validators {
		if int(index) >= len(candidates) || seen[index] || len(info.BLSPublicKeys[i]) != 48 || candidates[index].Key != digest(info.BLSPublicKeys[i]) {
			return false
		}
		seen[index] = true
	}
	return true
}

func sameStorageTargets(a, b map[string]ContractStorage) bool {
	if len(a) != len(b) {
		return false
	}
	for address := range a {
		if _, ok := b[address]; !ok {
			return false
		}
	}
	return true
}

func storageSubsetMatches(subset, all map[string]ContractStorage) bool {
	for address, value := range subset {
		if other, found := all[address]; !found || value != other {
			return false
		}
	}
	return true
}

func validateTransitions(report TransitionReport, source snapshot, origin Origin) error {
	if report.Protocol != TransitionProtocol || validate(report.Execution, source, origin) != nil || report.Blocks == nil || report.Transactions == nil || len(report.Blocks) != len(source.source.Blocks) || len(report.Transactions) != len(report.Execution.Transactions) {
		return ErrSource
	}
	blocks := make(map[string]BlockTransition)
	last := make(map[string]map[string]ContractStorage)
	for i, block := range report.Blocks {
		if block.Index != source.source.Blocks[i].Index || block.Genesis != (i == 0) || !source.extraValid[block.Index] {
			return ErrSource
		}
		before, ok := storageAccountMap(block.BeforeSystem)
		if !ok {
			return ErrSource
		}
		start, ok := storageAccountMap(block.BeforeTransactions)
		if !ok {
			return ErrSource
		}
		end, ok := storageAccountMap(block.AfterTransactions)
		if !ok {
			return ErrSource
		}
		final, ok := storageAccountMap(block.Finalized)
		if !ok {
			return ErrSource
		}
		if i == 0 {
			if len(before) != 0 || len(start) != 0 || len(end) != 0 {
				return ErrSource
			}
		} else if !sameStorageTargets(before, start) || !sameStorageTargets(start, end) || !sameStorageTargets(end, final) {
			return ErrSource
		}
		epoch := source.epochs[block.Index]
		if (epoch == nil) != (block.EpochRegistry == nil) {
			return ErrSource
		}
		if block.EpochRegistry != nil {
			read := *block.EpochRegistry
			if !validRegistryRead(read) || !registryMatchesAccount(read, final) {
				return ErrSource
			}
			if i > 0 && read.Status == "observed" && !epochRegistryMatches(epoch, read) {
				return ErrSource
			}
		}
		blocks[block.Index] = block
	}
	writes := 0
	for i, point := range report.Transactions {
		block, ok := blocks[point.Index]
		if !ok || block.Genesis || !validTransitionPoint(point, report.Execution.Transactions[i], block) {
			return ErrSource
		}
		before, _ := storageAccountMap(point.AccountsBefore)
		after, _ := storageAccountMap(point.AccountsAfter)
		start, _ := storageAccountMap(block.BeforeTransactions)
		if previous, found := last[point.Index]; found {
			if !reflect.DeepEqual(previous, before) {
				return ErrSource
			}
		} else if !storageSubsetMatches(before, start) {
			return ErrSource
		}
		last[point.Index] = after
		writes += len(point.Writes)
		if writes > 100000 {
			return ErrSource
		}
	}
	for _, block := range report.Blocks {
		end, _ := storageAccountMap(block.AfterTransactions)
		if previous, found := last[block.Index]; found {
			if !storageSubsetMatches(previous, end) {
				return ErrSource
			}
		} else if !reflect.DeepEqual(block.BeforeTransactions, block.AfterTransactions) {
			return ErrSource
		}
	}
	return nil
}
