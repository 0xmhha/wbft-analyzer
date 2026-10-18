package main

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

func storageFixture(t *testing.T, childReverts, parentReverts, delegate bool) *storageObserver {
	t.Helper()
	mem := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { _ = mem.Close() })
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(mem), nil)
	if err != nil {
		t.Fatal(err)
	}
	parent, child, untouched := common.HexToAddress("0x10000"), common.HexToAddress("0x20000"), common.HexToAddress("0x40000")
	caller := common.HexToAddress("0x30000")
	childCode := []byte{byte(vm.PUSH1), 7, byte(vm.PUSH1), 1, byte(vm.SSTORE)}
	if childReverts {
		childCode = append(childCode, byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.REVERT))
	} else {
		childCode = append(childCode, byte(vm.STOP))
	}
	code := []byte{byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.PUSH1), 0}
	if !delegate {
		code = append(code, byte(vm.PUSH1), 0)
	}
	code = append(code, byte(vm.PUSH20))
	code = append(code, child[:]...)
	code = append(code, byte(vm.PUSH3), 3, 0x0d, 0x40)
	if delegate {
		code = append(code, byte(vm.DELEGATECALL))
	} else {
		code = append(code, byte(vm.CALL))
	}
	code = append(code, byte(vm.POP), byte(vm.PUSH1), 9, byte(vm.PUSH1), 0, byte(vm.SSTORE))
	if parentReverts {
		code = append(code, byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.REVERT))
	} else {
		code = append(code, byte(vm.STOP))
	}
	st.SetCode(parent, code)
	st.SetCode(child, childCode)
	st.SetCode(untouched, []byte{byte(vm.STOP)})
	st.SetNonce(caller, 1)
	cfg := *params.AllEthashProtocolChanges
	cfg.ShanghaiTime = nil
	cfg.CancunTime = nil
	rules := cfg.Rules(big.NewInt(1), false, 1)
	st.Prepare(rules, caller, common.Address{}, &parent, vm.ActivePrecompiles(rules), nil, nil)
	observer, err := newStorageObserver(st, &capture{ctx: context.Background(), authorityIndex: "0"}, []common.Address{parent, child, untouched})
	if err != nil {
		t.Fatal(err)
	}
	env := vm.NewEVM(vm.BlockContext{CanTransfer: core.CanTransfer, Transfer: core.Transfer,
		BlockNumber: big.NewInt(1), GasLimit: 1000000, Time: 1, BaseFee: big.NewInt(0)}, vm.TxContext{}, observer, &cfg, vm.Config{Tracer: observer.trace})
	observer.trace.CaptureTxStart(env, 1000000, nil)
	_, _, callErr := env.Call(vm.AccountRef(caller), parent, nil, 1000000, common.U2560)
	observer.trace.CaptureTxEnd(0)
	if (callErr != nil) != parentReverts {
		t.Fatal("unexpected fixture execution result", callErr)
	}
	return observer
}

func TestStorageObservationAllowsUnrelatedCreation(t *testing.T) {
	mem := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { _ = mem.Close() })
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(mem), nil)
	if err != nil {
		t.Fatal(err)
	}
	parent, caller := common.HexToAddress("0x50000"), common.HexToAddress("0x60000")
	// The factory deploys an unrelated account whose constructor stores a word.
	init := []byte{byte(vm.PUSH1), 7, byte(vm.PUSH1), 1, byte(vm.SSTORE), byte(vm.STOP)}
	code := []byte{byte(vm.PUSH1), byte(len(init)), byte(vm.PUSH1), 16, byte(vm.PUSH1), 0, byte(vm.CODECOPY),
		byte(vm.PUSH1), byte(len(init)), byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.CREATE), byte(vm.POP), byte(vm.STOP)}
	st.SetCode(parent, append(code, init...))
	st.SetNonce(caller, 1)
	cfg := *params.AllEthashProtocolChanges
	cfg.ShanghaiTime = nil
	cfg.CancunTime = nil
	rules := cfg.Rules(big.NewInt(1), false, 1)
	st.Prepare(rules, caller, common.Address{}, &parent, vm.ActivePrecompiles(rules), nil, nil)
	observer, err := newStorageObserver(st, &capture{ctx: context.Background(), authorityIndex: "0"}, []common.Address{parent})
	if err != nil {
		t.Fatal(err)
	}
	env := vm.NewEVM(vm.BlockContext{CanTransfer: core.CanTransfer, Transfer: core.Transfer,
		BlockNumber: big.NewInt(1), GasLimit: 1000000, Time: 1, BaseFee: big.NewInt(0)}, vm.TxContext{}, observer, &cfg, vm.Config{Tracer: observer.trace})
	observer.trace.CaptureTxStart(env, 1000000, nil)
	_, _, err = env.Call(vm.AccountRef(caller), parent, nil, 1000000, common.U2560)
	observer.trace.CaptureTxEnd(0)
	created := crypto.CreateAddress(parent, 0)
	if err != nil || st.GetState(created, common.HexToHash("0x1")) != common.HexToHash("0x7") || !st.Exist(created) {
		t.Fatal("constructor did not execute the distinct account's storage write", err)
	}
	result, err := observer.finish(true)
	if err != nil {
		t.Fatal("unrelated account creation prevented configured-target verification", err)
	}
	if len(result.writes) != 0 || len(result.before) != 1 || result.before[0].owner != parent {
		t.Fatal("unrelated constructor was projected as a configured-target effect")
	}
}

func TestStorageObservationRollbackAndOwner(t *testing.T) {
	t.Run("caught child revert preserves parent effect", func(t *testing.T) {
		result, err := storageFixture(t, true, false, false).finish(true)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.writes) != 2 || !result.writes[0].reverted || result.writes[1].reverted {
			t.Fatal("caught revert lost its actual scope")
		}
	})
	t.Run("ancestor revert cancels successful child", func(t *testing.T) {
		result, err := storageFixture(t, false, true, false).finish(true)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.writes) != 2 || !result.writes[0].reverted || !result.writes[1].reverted {
			t.Fatal("ancestor revert left an effective child write")
		}
	})
	t.Run("delegate execution retains caller storage", func(t *testing.T) {
		result, err := storageFixture(t, false, false, true).finish(true)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.writes) != 2 {
			t.Fatal("missing writes")
		}
		child, parent := result.writes[0], result.writes[1]
		if child.owner != parent.owner || child.instruction.owner != child.owner || child.instruction.codeReference == child.owner || child.instruction.code == child.code {
			t.Fatal("delegate code reference was confused with the storage owner")
		}
		if child.instruction.pc != 4 || child.instruction.key != common.HexToHash("0x1") || child.instruction.value != common.HexToHash("0x7") {
			t.Fatal("instruction position or operands differ")
		}
	})
}

func TestStorageObservationRejectsUnexplainedTargets(t *testing.T) {
	t.Run("unmentioned configured storage mutation", func(t *testing.T) {
		observer := storageFixture(t, false, false, false)
		untouched := common.HexToAddress("0x40000")
		for _, write := range observer.writes {
			if write.owner == untouched {
				t.Fatal("fixture target was unexpectedly touched")
			}
		}
		observer.StateDB.SetState(untouched, common.HexToHash("0x33"), common.HexToHash("0x9"))
		if _, err := observer.finish(true); err == nil {
			t.Fatal("unobserved configured-target storage change was accepted")
		}
	})
	t.Run("unmentioned configured code mutation", func(t *testing.T) {
		observer := storageFixture(t, false, false, false)
		observer.SetCode(common.HexToAddress("0x40000"), []byte{byte(vm.PUSH1), 0, byte(vm.STOP)})
		if _, err := observer.finish(true); err == nil {
			t.Fatal("unobserved configured-target code change was accepted")
		}
	})
	t.Run("storage method without instruction provenance", func(t *testing.T) {
		observer := storageFixture(t, false, false, false)
		observer.SetState(common.HexToAddress("0x10000"), common.HexToHash("0x33"), common.HexToHash("0x9"))
		if _, err := observer.finish(true); err == nil {
			t.Fatal("write outside an observed VM instruction was accepted")
		}
	})
}
