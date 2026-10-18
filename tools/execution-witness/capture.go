package main

import (
	"context"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

type observedFrame struct {
	Frame
	creation bool
	returned []byte
	parent   int
	children uint32
}
type capture struct {
	ctx            context.Context
	env            *vm.EVM
	stop           func() bool
	contracts      params.SystemContracts
	authorityIndex string
	frames         []observedFrame
	stack          []int
	starts, ends   int
	bad            bool
}

func (t *capture) push(kind string, from, to common.Address, creation bool, input []byte, gas uint64) {
	if t.bad {
		return
	}
	if len(t.frames) >= 4096 || len(t.stack) >= 128 || len(input) > MaxSourceBytes || t.env == nil {
		t.bad = true
		if t.env != nil {
			t.env.Cancel()
		}
		return
	}
	f := observedFrame{creation: creation, parent: -1, Frame: Frame{Path: []uint32{}, Kind: kind, From: strings.ToLower(from.Hex()), To: strings.ToLower(to.Hex()), Input: digest(input), Selector: selector(input), Gas: strconv.FormatUint(gas, 10), AuthorityIndex: t.authorityIndex, AccountCodeHash: strings.ToLower(t.env.StateDB.GetCodeHash(to).Hex()), AccountCodeBytes: len(t.env.StateDB.GetCode(to)), Observation: "call_hook"}}
	if len(t.stack) > 0 {
		i := t.stack[len(t.stack)-1]
		parent := &t.frames[i]
		f.parent = i
		f.Path = append(append([]uint32{}, parent.Path...), parent.children)
		parent.children++
	} else if len(t.frames) != 0 {
		t.bad = true
		t.env.Cancel()
		return
	}
	t.frames = append(t.frames, f)
	t.stack = append(t.stack, len(t.frames)-1)
}
func (t *capture) pop(output []byte, gas uint64, err error) {
	if t.bad {
		return
	}
	if len(t.stack) == 0 || len(output) > MaxSourceBytes {
		t.bad = true
		t.env.Cancel()
		return
	}
	i := t.stack[len(t.stack)-1]
	f := &t.frames[i]
	f.Return = digest(output)
	if i == 0 {
		f.returned = append([]byte{}, output...)
	}
	f.GasUsed = strconv.FormatUint(gas, 10)
	f.Status, f.VMError = vmError(err)
	interpret(&f.Frame, t.contracts, f.creation, output)
	t.stack = t.stack[:len(t.stack)-1]
}
func (t *capture) CaptureTxStart(env *vm.EVM, _ uint64, _ []types.SetCodeAuthorization) {
	t.starts++
	t.env = env
	t.stop = context.AfterFunc(t.ctx, env.Cancel)
}
func (t *capture) CaptureTxEnd(_ uint64) {
	t.ends++
	if t.stop != nil {
		t.stop()
	}
}
func (t *capture) CaptureStart(from, to common.Address, creation bool, input []byte, gas uint64, _ *big.Int) {
	kind := "CALL"
	if creation {
		kind = "CREATE"
	}
	t.push(kind, from, to, creation, input, gas)
}
func (t *capture) CaptureEnd(output []byte, gas uint64, err error) {
	if !t.bad && len(t.stack) != 1 {
		t.bad = true
		t.env.Cancel()
		return
	}
	t.pop(output, gas, err)
}
func (t *capture) CaptureEnter(op vm.OpCode, from, to common.Address, input []byte, gas uint64, _ *big.Int) {
	if !t.bad && len(t.stack) == 0 {
		t.bad = true
		t.env.Cancel()
		return
	}
	t.push(op.String(), from, to, op == vm.CREATE || op == vm.CREATE2, input, gas)
}
func (t *capture) CaptureExit(output []byte, gas uint64, err error) {
	if !t.bad && len(t.stack) < 2 {
		t.bad = true
		t.env.Cancel()
		return
	}
	t.pop(output, gas, err)
}
func (*capture) CaptureState(uint64, vm.OpCode, uint64, uint64, *vm.ScopeContext, []byte, int, error) {
}
func (*capture) CaptureFault(uint64, vm.OpCode, uint64, uint64, *vm.ScopeContext, int, error) {}
func (t *capture) projection() ([]Frame, error) {
	if t.bad || t.starts != 1 || t.ends != 1 || len(t.stack) != 0 {
		return nil, ErrInput
	}
	out := make([]Frame, 0, len(t.frames))
	for i := range t.frames {
		f := t.frames[i].Frame
		f.Effective = f.Status == "succeeded"
		if parent := t.frames[i].parent; parent >= 0 {
			f.Effective = f.Effective && out[parent].Effective
		}
		out = append(out, f)
	}
	return out, nil
}
