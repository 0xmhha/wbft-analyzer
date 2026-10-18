package main

import (
	"bytes"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
)

const maxTransactionStorageWrites = 10000
const maxStorageTargets = 16

// Raw operands stay inside replay. Public projections must use reviewed
// semantics or digests rather than serializing these internal observations.
type storageInstruction struct {
	pc                   uint64
	owner, codeReference common.Address
	code                 common.Hash
	key, value           common.Hash
	frame                int
}

type storageTrace struct {
	*capture
	pending *storageInstruction
	targets map[common.Address]bool
}

func (t *storageTrace) CaptureState(pc uint64, op vm.OpCode, _, _ uint64, scope *vm.ScopeContext, _ []byte, _ int, err error) {
	t.pending = nil
	if op != vm.SSTORE || err != nil || t.bad {
		return
	}
	if !t.targets[scope.Contract.Address()] {
		return
	}
	values := scope.Stack.Data()
	if len(values) < 2 || pc >= uint64(len(scope.Contract.Code)) || scope.Contract.Code[pc] != byte(vm.SSTORE) || len(t.stack) == 0 {
		t.bad = true
		if t.env != nil {
			t.env.Cancel()
		}
		return
	}
	reference := common.Address{}
	if scope.Contract.CodeAddr != nil {
		reference = *scope.Contract.CodeAddr
	}
	t.pending = &storageInstruction{pc: pc, owner: scope.Contract.Address(), codeReference: reference,
		code: crypto.Keccak256Hash(scope.Contract.Code), key: values[len(values)-1].Bytes32(),
		value: values[len(values)-2].Bytes32(), frame: t.stack[len(t.stack)-1]}
}

func (t *storageTrace) CaptureFault(uint64, vm.OpCode, uint64, uint64, *vm.ScopeContext, int, error) {
	t.pending = nil
}

type storageMutation struct {
	owner                    common.Address
	key, before, after, code common.Hash
	frame                    int
	path                     []uint32
	instruction              *storageInstruction
	reverted                 bool
}

type storageRevision struct{ id, position int }

type storageObserver struct {
	*state.StateDB
	initial   *state.StateDB
	trace     *storageTrace
	targets   []common.Address
	writes    []storageMutation
	revisions []storageRevision
	bad       bool
}

func newStorageObserver(st *state.StateDB, tracer *capture, targets []common.Address) (*storageObserver, error) {
	if st == nil || tracer == nil || tracer.ctx == nil || len(targets) == 0 || len(targets) > maxStorageTargets {
		return nil, ErrInput
	}
	seen := make(map[common.Address]bool)
	for _, target := range targets {
		if target == (common.Address{}) {
			return nil, ErrInput
		}
		seen[target] = true
	}
	ordered := sortedStorageAddresses(seen)
	return &storageObserver{StateDB: st, initial: st.Copy(), trace: &storageTrace{capture: tracer, targets: seen}, targets: ordered}, nil
}

func (o *storageObserver) fail() {
	o.bad = true
	if o.trace.env != nil {
		o.trace.env.Cancel()
	}
}

func (o *storageObserver) SetState(owner common.Address, key, value common.Hash) {
	// Replay still executes every account. Only explicit targets contribute to
	// this storage observation; unrelated deployment is not a target mutation.
	if !o.trace.targets[owner] {
		o.trace.pending = nil
		o.StateDB.SetState(owner, key, value)
		return
	}
	if o.bad || len(o.writes) >= maxTransactionStorageWrites {
		o.fail()
		o.StateDB.SetState(owner, key, value)
		return
	}
	mutation := storageMutation{owner: owner, key: key, before: o.GetState(owner, key),
		code: o.GetCodeHash(owner), frame: -1, path: []uint32{}}
	if len(o.trace.stack) > 0 {
		mutation.frame = o.trace.stack[len(o.trace.stack)-1]
		mutation.path = append(mutation.path, o.trace.frames[mutation.frame].Path...)
	}
	if instruction := o.trace.pending; instruction != nil {
		if instruction.owner != owner || instruction.key != key || instruction.value != value || instruction.frame != mutation.frame {
			o.fail()
		} else {
			mutation.instruction = instruction
		}
	}
	o.trace.pending = nil
	o.StateDB.SetState(owner, key, value)
	mutation.after = o.GetState(owner, key)
	if mutation.after != value || o.Error() != nil {
		o.fail()
	}
	o.writes = append(o.writes, mutation)
}

func (o *storageObserver) Snapshot() int {
	id := o.StateDB.Snapshot()
	if o.bad || len(o.revisions) >= maxTransactionStorageWrites {
		o.fail()
		return id
	}
	o.revisions = append(o.revisions, storageRevision{id, len(o.writes)})
	return id
}

func (o *storageObserver) RevertToSnapshot(id int) {
	if o.bad {
		o.StateDB.RevertToSnapshot(id)
		return
	}
	position := -1
	for i := len(o.revisions) - 1; i >= 0; i-- {
		if o.revisions[i].id == id {
			position = i
			break
		}
	}
	if position < 0 {
		o.fail()
		o.StateDB.RevertToSnapshot(id)
		return
	}
	o.StateDB.RevertToSnapshot(id)
	for i := o.revisions[position].position; i < len(o.writes); i++ {
		o.writes[i].reverted = true
	}
	o.revisions = o.revisions[:position]
}

type storageAccount struct {
	owner      common.Address
	root, code common.Hash
	exists     bool
}

type storageObservation struct {
	writes        []storageMutation
	before, after []storageAccount
}

func sortedStorageAddresses(set map[common.Address]bool) []common.Address {
	addresses := make([]common.Address, 0, len(set))
	for address := range set {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return bytes.Compare(addresses[i][:], addresses[j][:]) < 0 })
	return addresses
}

func storageAccounts(st *state.StateDB, addresses []common.Address, deleteEmpty bool) ([]storageAccount, error) {
	copy := st.Copy()
	copy.IntermediateRoot(deleteEmpty)
	if copy.Error() != nil {
		return nil, ErrInput
	}
	out := make([]storageAccount, 0, len(addresses))
	for _, address := range addresses {
		out = append(out, storageAccount{owner: address, root: copy.GetStorageRoot(address), code: copy.GetCodeHash(address), exists: copy.Exist(address)})
	}
	return out, nil
}

// finish checks configured targets even when no SetState hook mentioned them.
// Unexplained writes, unobserved native mutations and account lifecycle changes
// cannot produce a complete storage observation through this path.
func (o *storageObserver) finish(deleteEmpty bool) (storageObservation, error) {
	if o.bad || o.trace.bad || o.Error() != nil {
		return storageObservation{}, ErrInput
	}
	frames, err := o.trace.projection()
	if err != nil {
		return storageObservation{}, err
	}
	addresses := make(map[common.Address]bool)
	for _, address := range o.targets {
		addresses[address] = true
	}
	reconstructed := o.initial.Copy()
	type location struct {
		owner common.Address
		key   common.Hash
	}
	values := make(map[location]common.Hash)
	for _, mutation := range o.writes {
		if !addresses[mutation.owner] {
			return storageObservation{}, ErrInput
		}
		if mutation.reverted {
			continue
		}
		if mutation.frame < 0 || mutation.frame >= len(frames) || !frames[mutation.frame].Effective || mutation.instruction == nil {
			return storageObservation{}, ErrInput
		}
		key := location{mutation.owner, mutation.key}
		value, ok := values[key]
		if !ok {
			value = o.initial.GetState(key.owner, key.key)
		}
		if value != mutation.before {
			return storageObservation{}, ErrInput
		}
		values[key] = mutation.after
		reconstructed.SetState(key.owner, key.key, mutation.after)
	}
	for key, value := range values {
		if o.GetState(key.owner, key.key) != value {
			return storageObservation{}, ErrInput
		}
	}
	ordered := sortedStorageAddresses(addresses)
	before, err := storageAccounts(o.initial, ordered, deleteEmpty)
	if err != nil {
		return storageObservation{}, err
	}
	after, err := storageAccounts(o.StateDB, ordered, deleteEmpty)
	if err != nil {
		return storageObservation{}, err
	}
	expected, err := storageAccounts(reconstructed, ordered, deleteEmpty)
	if err != nil {
		return storageObservation{}, err
	}
	for i := range after {
		if after[i].code != before[i].code || after[i].exists != before[i].exists || after[i].root != expected[i].root {
			return storageObservation{}, ErrInput
		}
	}
	return storageObservation{writes: o.writes, before: before, after: after}, nil
}
