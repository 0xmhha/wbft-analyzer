package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/wbft"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

type transitionCapture struct {
	ctx          context.Context
	blocks       []BlockTransition
	transactions []TransactionTransition
	bytes        int
	writes       int
}

func verifyTransitions(ctx context.Context, raw []byte, root *os.Root) (TransitionReport, error) {
	observed := &transitionCapture{ctx: ctx, blocks: []BlockTransition{}, transactions: []TransactionTransition{}}
	execution, err := verifyReplay(ctx, raw, root, observed)
	if err != nil {
		return TransitionReport{}, err
	}
	if len(observed.blocks) != len(execution.Source.Blocks) || len(observed.transactions) != len(execution.Transactions) {
		return TransitionReport{}, ErrInput
	}
	report := TransitionReport{Protocol: TransitionProtocol, Execution: execution, Blocks: observed.blocks, Transactions: observed.transactions}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > MaxProjectionBytes || ctx.Err() != nil {
		return TransitionReport{}, ErrInput
	}
	return report, nil
}

func governanceTargets(sc ...params.SystemContracts) []common.Address {
	set := make(map[common.Address]bool)
	for _, contracts := range sc {
		if contracts.GovValidator != nil && contracts.GovValidator.Address != (common.Address{}) {
			set[contracts.GovValidator.Address] = true
		}
		if contracts.GovCouncil != nil && contracts.GovCouncil.Address != (common.Address{}) {
			set[contracts.GovCouncil.Address] = true
		}
	}
	return sortedStorageAddresses(set)
}

func projectAccounts(accounts []storageAccount) []ContractStorage {
	out := make([]ContractStorage, 0, len(accounts))
	for _, account := range accounts {
		out = append(out, ContractStorage{Address: strings.ToLower(account.owner.Hex()), CodeHash: account.code.Hex(), StorageRoot: account.root.Hex(), Exists: account.exists})
	}
	return out
}

func contractStorage(st *state.StateDB, targets []common.Address, deleteEmpty bool) ([]ContractStorage, error) {
	accounts, err := storageAccounts(st, targets, deleteEmpty)
	if err != nil {
		return nil, err
	}
	return projectAccounts(accounts), nil
}

func (c *transitionCapture) budget(value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > MaxProjectionBytes-c.bytes || c.ctx.Err() != nil {
		return ErrInput
	}
	c.bytes += len(raw)
	return nil
}

func (c *transitionCapture) beginBlock(header *types.Header, st *state.StateDB, cfg *wbft.Config, chain *params.ChainConfig, genesis bool) error {
	n := new(big.Int).Set(header.Number)
	parent := new(big.Int).Set(n)
	if parent.Sign() > 0 {
		parent.Sub(parent, big.NewInt(1))
	}
	targets := governanceTargets(cfg.GetSystemContracts(parent, chain), cfg.GetSystemContracts(n, chain))
	accounts, err := contractStorage(st, targets, chain.IsEIP158(n))
	if err != nil {
		return err
	}
	block := BlockTransition{Index: n.String(), Genesis: genesis, BeforeSystem: accounts, BeforeTransactions: []ContractStorage{}, AfterTransactions: []ContractStorage{}, Finalized: []ContractStorage{}}
	if genesis {
		block.BeforeSystem = []ContractStorage{}
		block.Finalized = accounts
	}
	c.blocks = append(c.blocks, block)
	return nil
}

func (c *transitionCapture) blockPhase(header *types.Header, st *state.StateDB, cfg *wbft.Config, chain *params.ChainConfig, phase string) error {
	if len(c.blocks) == 0 || c.blocks[len(c.blocks)-1].Index != header.Number.String() {
		return ErrInput
	}
	parent := new(big.Int).Set(header.Number)
	if parent.Sign() > 0 {
		parent.Sub(parent, big.NewInt(1))
	}
	targets := governanceTargets(cfg.GetSystemContracts(parent, chain), cfg.GetSystemContracts(header.Number, chain))
	accounts, err := contractStorage(st, targets, chain.IsEIP158(header.Number))
	if err != nil {
		return err
	}
	block := &c.blocks[len(c.blocks)-1]
	switch phase {
	case "before_transactions":
		block.BeforeTransactions = accounts
	case "after_transactions":
		block.AfterTransactions = accounts
	case "finalized":
		block.Finalized = accounts
		extra, err := types.ExtractWBFTExtra(header)
		if err != nil {
			return ErrInput
		}
		if extra.EpochInfo != nil {
			registry := registryRead(c.ctx, st, cfg.GetSystemContracts(header.Number, chain), chain.IsEIP158(header.Number))
			block.EpochRegistry = &registry
		}
		if !block.Genesis {
			for i := len(c.transactions) - 1; i >= 0 && c.transactions[i].Index == block.Index; i-- {
				point := &c.transactions[i]
				if point.RegistryAfter.State == nil {
					continue
				}
				address := point.RegistryAfter.State.Address
				if storagePhaseChanged(block.BeforeSystem, block.BeforeTransactions, address) || storagePhaseChanged(block.AfterTransactions, block.Finalized, address) {
					point.CauseStatus, point.Reason = "unestablished", "system_effects_overlap"
				}
			}
		}
		return c.budget(block)
	default:
		return ErrInput
	}
	return nil
}

func storagePhaseChanged(before, after []ContractStorage, address string) bool {
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

func (c *transitionCapture) transaction(header *types.Header, tx *types.Transaction, ordinal int, sc params.SystemContracts, primary *state.StateDB, observer *storageObserver, execution Transaction, deleteEmpty bool) error {
	point := TransactionTransition{Index: header.Number.String(), Ordinal: ordinal, Hash: strings.ToLower(tx.Hash().Hex()), BlockHash: strings.ToLower(header.Hash().Hex()), Status: "observed", Reason: "no_registry_change", AccountsBefore: []ContractStorage{}, AccountsAfter: []ContractStorage{}, Writes: []StorageWrite{}, Effects: []RegistryEffect{}, CauseStatus: "unestablished"}
	if observer == nil {
		point.Status, point.Reason = "unavailable", "unconfigured_authority"
		point.RegistryBefore = RegistryRead{Status: "unavailable", Reason: "unconfigured_authority"}
		point.RegistryAfter = point.RegistryBefore
	} else {
		observation, err := observer.finish(deleteEmpty)
		if err != nil {
			return err
		}
		shadowFrames, err := observer.trace.projection()
		if err != nil {
			return err
		}
		noCallHook := len(shadowFrames) == 0 && len(execution.Frames) == 1 && execution.Frames[0].Observation == "execution_result" && len(observation.writes) == 0
		if !reflect.DeepEqual(shadowFrames, execution.Frames) && !noCallHook {
			return ErrInput
		}
		point.AccountsBefore, point.AccountsAfter = projectAccounts(observation.before), projectAccounts(observation.after)
		point.RegistryBefore = registryRead(c.ctx, observer.initial, sc, deleteEmpty)
		point.RegistryAfter = registryRead(c.ctx, primary, sc, deleteEmpty)
		for _, mutation := range observation.writes {
			write := StorageWrite{Address: strings.ToLower(mutation.owner.Hex()), SlotSHA256: digest(mutation.key[:]).SHA256, Before: digest(mutation.before[:]), After: digest(mutation.after[:]), OwnerCodeHash: mutation.code.Hex(), Frame: mutation.frame, Path: append([]uint32{}, mutation.path...), Reverted: mutation.reverted}
			if instruction := mutation.instruction; instruction != nil {
				write.Instruction = &StorageInstruction{PC: strconv.FormatUint(instruction.pc, 10), CodeReference: strings.ToLower(instruction.codeReference.Hex()), CodeHash: instruction.code.Hex()}
			}
			point.Writes = append(point.Writes, write)
		}
		c.writes += len(point.Writes)
		if c.writes > 100000 {
			return ErrInput
		}
		point.Effects = registryEffects(point.RegistryBefore, point.RegistryAfter)
		point.Method, point.ProposalBefore, point.ProposalAfter = proposalContext(c.ctx, tx.Data(), observer.initial, primary, execution, sc)
		if point.RegistryBefore.Status != "observed" || point.RegistryAfter.Status != "observed" {
			point.Reason = "unavailable_registry_state"
		} else if len(point.Effects) > 0 {
			point.Reason = "unmapped_execution"
			if rootRegistryExecution(execution, point.Method, sc, observation.writes) {
				point.CauseStatus, point.Reason = "verified_transaction_effect", "reviewed_runtime_writes"
			}
		} else if execution.ReceiptStatus == "failed" {
			point.Reason = "reverted_transaction"
		}
	}
	if c.ctx.Err() != nil || c.budget(point) != nil {
		return ErrInput
	}
	c.transactions = append(c.transactions, point)
	return nil
}

func registryEffects(before, after RegistryRead) []RegistryEffect {
	out := []RegistryEffect{}
	if before.Status != "observed" || after.Status != "observed" || before.State == nil || after.State == nil || before.State.Address != after.State.Address || before.State.CodeHash != after.State.CodeHash {
		return out
	}
	old, current := make(map[string]RegistryCandidate), make(map[string]RegistryCandidate)
	for _, candidate := range before.State.Candidates {
		old[candidate.Address] = candidate
	}
	for _, candidate := range after.State.Candidates {
		current[candidate.Address] = candidate
	}
	for _, candidate := range before.State.Candidates {
		previous := candidate
		next, exists := current[candidate.Address]
		if !exists {
			out = append(out, RegistryEffect{Kind: "candidate_removed", Candidate: candidate.Address, Before: &previous})
			continue
		}
		if candidate.Key == next.Key && candidate.Operator == next.Operator {
			continue
		}
		kind := "candidate_updated"
		if candidate.Key == next.Key {
			kind = "operator_changed"
		} else if candidate.Operator == next.Operator {
			kind = "candidate_key_changed"
		}
		out = append(out, RegistryEffect{Kind: kind, Candidate: candidate.Address, Before: &previous, After: &next})
	}
	for _, candidate := range after.State.Candidates {
		if _, exists := old[candidate.Address]; !exists {
			next := candidate
			out = append(out, RegistryEffect{Kind: "candidate_added", Candidate: candidate.Address, After: &next})
		}
	}
	if len(out) == 0 && !reflect.DeepEqual(before.State.Candidates, after.State.Candidates) {
		out = append(out, RegistryEffect{Kind: "candidate_order_changed"})
	}
	return out
}

func rootRegistryExecution(execution Transaction, method string, sc params.SystemContracts, writes []storageMutation) bool {
	if method == "" || execution.ReceiptStatus != "succeeded" || sc.GovValidator == nil || len(execution.Frames) == 0 {
		return false
	}
	root := execution.Frames[0]
	address := sc.GovValidator.Address
	if root.Kind != "CALL" || len(root.Path) != 0 || !root.Effective || root.Authority != "gov_validator" || root.AccountCodeHash != validatorProfile.code.Hex() || root.To != strings.ToLower(address.Hex()) {
		return false
	}
	active := false
	for _, write := range writes {
		if write.reverted {
			continue
		}
		if write.owner != address || write.frame != 0 || write.instruction == nil || write.instruction.codeReference != address || write.instruction.code != validatorProfile.code || write.code != validatorProfile.code {
			return false
		}
		active = true
	}
	return active
}

var transitionABI = func() abi.ABI {
	entries := []map[string]any{}
	add := func(name string, types ...string) {
		inputs := []map[string]string{}
		for _, kind := range types {
			inputs = append(inputs, map[string]string{"type": kind})
		}
		entries = append(entries, map[string]any{"type": "function", "name": name, "inputs": inputs, "outputs": []any{}})
	}
	for _, name := range []string{"approveProposal", "disapproveProposal", "cancelProposal", "executeProposal", "executeWithFailure", "expireProposal"} {
		add(name, "uint256")
	}
	add("changeMember", "address")
	add("configureValidator", "address", "bytes", "bytes")
	add("proposeAddMember", "address", "uint32")
	add("proposeRemoveMember", "address", "uint32")
	add("proposeChangeQuorum", "uint32")
	add("proposeChangeMaxProposals", "uint256")
	add("proposeGasTip", "uint256")
	for _, name := range []string{"proposeAddBlacklist", "proposeRemoveBlacklist", "proposeAddAuthorizedAccount", "proposeRemoveAuthorizedAccount"} {
		add(name, "address")
		add(name+"Batch", "address[]")
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		panic("invalid transition ABI")
	}
	parsed, err := abi.JSON(bytes.NewReader(raw))
	if err != nil {
		panic("invalid transition ABI")
	}
	return parsed
}()

func proposalContext(ctx context.Context, input []byte, before, after *state.StateDB, execution Transaction, sc params.SystemContracts) (string, *ProposalState, *ProposalState) {
	if len(input) < 4 || len(input) > MaxSourceBytes || len(execution.Frames) == 0 {
		return "", nil, nil
	}
	root := execution.Frames[0]
	profile := validatorProfile.code
	switch root.Authority {
	case "gov_council":
		if sc.GovCouncil == nil || sc.GovCouncil.Version != "v1" || strings.ToLower(sc.GovCouncil.Address.Hex()) != root.To {
			return "", nil, nil
		}
		profile = councilProfile.code
	case "gov_validator":
		if sc.GovValidator == nil || sc.GovValidator.Version != "v1" || strings.ToLower(sc.GovValidator.Address.Hex()) != root.To {
			return "", nil, nil
		}
	default:
		return "", nil, nil
	}
	if root.Kind != "CALL" || root.AccountCodeHash != profile.Hex() {
		return "", nil, nil
	}
	method, err := transitionABI.MethodById(input[:4])
	if err != nil {
		return "", nil, nil
	}
	values, err := method.Inputs.Unpack(input[4:])
	if err != nil {
		return "", nil, nil
	}
	packed, err := method.Inputs.Pack(values...)
	if err != nil || !bytes.Equal(packed, input[4:]) {
		return "", nil, nil
	}
	address := common.HexToAddress(root.To)
	var id *big.Int
	if strings.HasPrefix(method.Name, "propose") {
		previous, current := before.GetState(address, stateSlot(2)).Big(), after.GetState(address, stateSlot(2)).Big()
		if current.Cmp(new(big.Int).Add(previous, big.NewInt(1))) == 0 {
			id = current
		}
	} else if strings.HasSuffix(method.Name, "Proposal") || method.Name == "executeWithFailure" {
		if len(values) == 1 {
			id, _ = values[0].(*big.Int)
		}
	}
	if id == nil {
		return method.Name, nil, nil
	}
	previous, err := readProposal(ctx, before, address, profile, id)
	if err != nil {
		return method.Name, nil, nil
	}
	current, err := readProposal(ctx, after, address, profile, id)
	if err != nil {
		return method.Name, nil, nil
	}
	return method.Name, previous, current
}
