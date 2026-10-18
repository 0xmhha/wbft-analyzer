package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/wbft"
	wbftengine "github.com/ethereum/go-ethereum/consensus/wbft/engine"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
)

// Context reads only already-processed headers and independently reconstructed
// state. Source-provided state roots are never used to fill missing trie data.
type chainContext struct {
	config  *params.ChainConfig
	states  state.Database
	headers map[uint64]*types.Header
	byHash  map[common.Hash]uint64
	td      map[uint64]*big.Int
	current uint64
}

func (*chainContext) Engine() consensus.Engine       { panic("explicit author required") }
func (c *chainContext) Config() *params.ChainConfig  { return c.config }
func (c *chainContext) CurrentHeader() *types.Header { return c.GetHeaderByNumber(c.current) }
func (c *chainContext) GetHeader(hash common.Hash, n uint64) *types.Header {
	h := c.GetHeaderByNumber(n)
	if h == nil || h.Hash() != hash {
		return nil
	}
	return h
}
func (c *chainContext) GetHeaderByNumber(n uint64) *types.Header {
	if n > c.current {
		return nil
	}
	h := c.headers[n]
	if h == nil {
		return nil
	}
	return types.CopyHeader(h)
}
func (c *chainContext) GetHeaderByHash(hash common.Hash) *types.Header {
	n, ok := c.byHash[hash]
	if !ok {
		return nil
	}
	return c.GetHeader(hash, n)
}
func (c *chainContext) GetTd(hash common.Hash, n uint64) *big.Int {
	if c.GetHeader(hash, n) == nil || c.td[n] == nil {
		return nil
	}
	return new(big.Int).Set(c.td[n])
}
func (c *chainContext) StateAt(root common.Hash) (*state.StateDB, error) {
	return state.New(root, c.states, nil)
}
func (c *chainContext) add(h *types.Header) {
	n := h.Number.Uint64()
	c.headers[n] = types.CopyHeader(h)
	c.byHash[h.Hash()] = n
	total := new(big.Int).Set(h.Difficulty)
	if n > 0 {
		total.Add(total, c.td[n-1])
	}
	c.td[n] = total
	c.current = n
}

func blockEvidence(b *types.Block, file Digest) BlockEvidence {
	return BlockEvidence{Index: b.Number().String(), Hash: strings.ToLower(b.Hash().Hex()), Parent: strings.ToLower(b.ParentHash().Hex()), StateRoot: strings.ToLower(b.Root().Hex()), TransactionRoot: strings.ToLower(b.TxHash().Hex()), ReceiptRoot: strings.ToLower(b.ReceiptHash().Hex()), GasUsed: strconv.FormatUint(b.GasUsed(), 10), File: file}
}

// A shadow ApplyMessage provides the actual outer execution result even when
// the VM rejects before emitting a call hook. Its state, logs and gas must match
// the normal ApplyTransaction path; it never replaces canonical processing.
func apply(ctx context.Context, chain *chainContext, header *types.Header, st *state.StateDB, tx *types.Transaction, ordinal int, gp *core.GasPool, used *uint64, contracts params.SystemContracts, parent string) (Transaction, *types.Receipt, error) {
	empty := Transaction{}
	if ctx.Err() != nil {
		return empty, nil, ErrInput
	}
	shadow := st.Copy()
	shadow.SetTxContext(tx.Hash(), ordinal)
	message, err := core.TransactionToMessage(tx, types.MakeSigner(chain.config, header.Number, header.Time), header.BaseFee, header.GasTip(), shadow)
	if err != nil {
		return empty, nil, ErrInput
	}
	context := core.NewEVMBlockContext(header, chain, &header.Coinbase)
	env := vm.NewEVM(context, core.NewEVMTxContext(message), shadow, chain.config, vm.Config{})
	stop := contextAfter(ctx, env.Cancel)
	raw, err := core.ApplyMessage(env, message, new(core.GasPool).AddGas(gp.Gas()))
	stop()
	if err != nil || raw == nil || ctx.Err() != nil || len(raw.ReturnData) > MaxSourceBytes {
		return empty, nil, ErrInput
	}
	if chain.config.IsByzantium(header.Number) {
		shadow.Finalise(true)
	} else {
		shadow.IntermediateRoot(chain.config.IsEIP158(header.Number))
	}
	st.SetTxContext(tx.Hash(), ordinal)
	t := &capture{ctx: ctx, contracts: contracts, authorityIndex: parent, frames: []observedFrame{}}
	receipt, err := core.ApplyTransaction(chain.config, chain, &header.Coinbase, gp, st, header, tx, used, vm.Config{Tracer: t})
	if t.stop != nil {
		t.stop()
	}
	if err != nil || receipt == nil || ctx.Err() != nil {
		return empty, nil, ErrInput
	}
	if raw.UsedGas != receipt.GasUsed || raw.Failed() != (receipt.Status == types.ReceiptStatusFailed) {
		return empty, nil, ErrInput
	}
	primary := st.Copy()
	if primary.IntermediateRoot(chain.config.IsEIP158(header.Number)) != shadow.IntermediateRoot(chain.config.IsEIP158(header.Number)) || primary.Error() != nil || shadow.Error() != nil {
		return empty, nil, ErrInput
	}
	a, err := json.Marshal(receipt.Logs)
	if err != nil {
		return empty, nil, ErrInput
	}
	b, err := json.Marshal(shadow.GetLogs(tx.Hash(), header.Number.Uint64(), header.Hash()))
	if err != nil || !bytes.Equal(a, b) {
		return empty, nil, ErrInput
	}
	frames, err := t.projection()
	if err != nil {
		return empty, nil, ErrInput
	}
	to := ""
	target := crypto.CreateAddress(message.From, tx.Nonce())
	creation := tx.To() == nil
	if !creation {
		target = *tx.To()
		to = strings.ToLower(target.Hex())
	}
	status, code := vmError(raw.Err)
	if len(frames) > 0 {
		f := frames[0]
		if f.From != strings.ToLower(message.From.Hex()) || f.To != strings.ToLower(target.Hex()) || f.Input != digest(tx.Data()) || f.Status != status || f.VMError != code || !bytes.Equal(t.frames[0].returned, raw.ReturnData) {
			return empty, nil, ErrInput
		}
	} else {
		kind := "CALL"
		if creation {
			kind = "CREATE"
		}
		f := Frame{Path: []uint32{}, Kind: kind, From: strings.ToLower(message.From.Hex()), To: strings.ToLower(target.Hex()), Input: digest(tx.Data()), Selector: selector(tx.Data()), Return: digest(raw.ReturnData), Status: status, VMError: code, Effective: raw.Err == nil, AuthorityIndex: parent, Observation: "execution_result"}
		interpret(&f, contracts, creation, raw.ReturnData)
		frames = append(frames, f)
	}
	rawReceipt, err := receipt.MarshalBinary()
	if err != nil {
		return empty, nil, ErrInput
	}
	receiptStatus := "succeeded"
	if raw.Failed() {
		receiptStatus = "failed"
	}
	logs, err := normalizeLogs(receipt.Logs)
	if err != nil {
		return empty, nil, err
	}
	return Transaction{Logs: logs, Index: header.Number.String(), Ordinal: ordinal, Hash: strings.ToLower(tx.Hash().Hex()), BlockHash: strings.ToLower(header.Hash().Hex()), From: strings.ToLower(message.From.Hex()), To: to, Input: digest(tx.Data()), Selector: selector(tx.Data()), GasUsed: strconv.FormatUint(receipt.GasUsed, 10), ReceiptStatus: receiptStatus, Receipt: digest(rawReceipt), Frames: frames}, receipt, nil
}
func normalizeLogs(logs []*types.Log) ([]Log, error) {
	if len(logs) > MaxTransactionLogs {
		return nil, ErrInput
	}
	out := make([]Log, 0, len(logs))
	for _, log := range logs {
		if log == nil || len(log.Topics) > 4 || len(log.Data) > MaxSourceBytes {
			return nil, ErrInput
		}
		item := Log{Address: strings.ToLower(log.Address.Hex()), Topics: []string{}, Data: digest(log.Data)}
		for _, topic := range log.Topics {
			item.Topics = append(item.Topics, strings.ToLower(topic.Hex()))
		}
		out = append(out, item)
	}
	return out, nil
}
func contextAfter(ctx context.Context, f func()) func() bool { return context.AfterFunc(ctx, f) }

func transactionAuthority(cfg *wbft.Config, chain *params.ChainConfig, number *big.Int) (params.SystemContracts, string, error) {
	if cfg == nil || chain == nil || number == nil || number.Sign() <= 0 || len(cfg.SystemContractUpgrades) == 0 {
		return params.SystemContracts{}, "", ErrInput
	}
	// Upgrades run after the block's transactions. ABI authority must describe
	// the parent-finalized contract state; VM fork rules still use this block.
	parent := new(big.Int).Sub(number, big.NewInt(1))
	return cfg.GetSystemContracts(parent, chain), parent.String(), nil
}

func verify(ctx context.Context, raw []byte, root *os.Root) (report Report, err error) {
	defer func() {
		if recover() != nil {
			report = Report{}
			err = ErrInput
		}
	}()
	m, g, source, r, err := loadManifest(ctx, raw, root)
	if err != nil {
		return Report{}, ErrInput
	}
	mem := rawdb.NewMemoryDatabase()
	defer mem.Close()
	tdb := triedb.NewDatabase(mem, triedb.HashDefaults)
	defer tdb.Close()
	_, hash, err := core.SetupGenesisBlock(mem, tdb, g)
	if err != nil {
		return Report{}, ErrInput
	}
	created := rawdb.ReadBlock(mem, hash, 0)
	if created == nil {
		return Report{}, ErrInput
	}
	original, file, err := r.block(m.Blocks[0])
	if err != nil || original.Hash() != created.Hash() || original.Root() != created.Root() || len(original.Transactions()) != 0 {
		return Report{}, ErrInput
	}
	source.GenesisHash = strings.ToLower(hash.Hex())
	source.Blocks = append(source.Blocks, blockEvidence(original, file))
	states := state.NewDatabaseWithNodeDB(mem, tdb)
	chain := &chainContext{config: g.Config, states: states, headers: map[uint64]*types.Header{}, byHash: map[common.Hash]uint64{}, td: map[uint64]*big.Int{}}
	chain.add(created.Header())
	cfg := new(wbft.Config)
	if ethconfig.SetConfigFromChainConfig(cfg, g.Config) != nil {
		return Report{}, ErrInput
	}
	engine := wbftengine.NewEngine(cfg, common.Address{}, nil, nil)
	report = Report{Protocol: Protocol, Origin: Origin{Path: OriginPath, Version: OriginVersion, Sum: OriginSum}, Source: source, Transactions: []Transaction{}}
	projectionBytes := 0
	frameCount := 0
	logCount := 0
	totalGas := uint64(0)
	for n := 1; n < len(m.Blocks); n++ {
		if ctx.Err() != nil {
			return Report{}, ErrInput
		}
		block, file, err := r.block(m.Blocks[n])
		if err != nil || block.ParentHash() != chain.CurrentHeader().Hash() || len(block.Withdrawals()) != 0 || block.GasUsed() > MaxTotalGas-totalGas {
			return Report{}, ErrInput
		}
		header := block.Header()
		parent := chain.CurrentHeader()
		st, err := state.New(parent.Root, states, nil)
		if err != nil {
			return Report{}, ErrInput
		}
		if g.Config.DAOForkSupport && g.Config.DAOForkBlock != nil && g.Config.DAOForkBlock.Cmp(header.Number) == 0 {
			misc.ApplyDAOHardFork(st)
		}
		if beacon := block.BeaconRoot(); beacon != nil {
			context := core.NewEVMBlockContext(header, chain, &header.Coinbase)
			env := vm.NewEVM(context, vm.TxContext{}, st, g.Config, vm.Config{})
			core.ProcessBeaconBlockRoot(*beacon, env, st)
		}
		if types.DeriveSha(block.Transactions(), trie.NewStackTrie(nil)) != block.TxHash() {
			return Report{}, ErrInput
		}
		gp := new(core.GasPool).AddGas(block.GasLimit())
		used := uint64(0)
		receipts := types.Receipts{}
		for i, tx := range block.Transactions() {
			if len(report.Transactions) >= MaxTransactions {
				return Report{}, ErrInput
			}
			contracts, authorityIndex, err := transactionAuthority(cfg, g.Config, header.Number)
			if err != nil {
				return Report{}, ErrInput
			}
			result, receipt, err := apply(ctx, chain, header, st, tx, i, gp, &used, contracts, authorityIndex)
			if err != nil {
				return Report{}, ErrInput
			}
			logCount += len(result.Logs)
			if logCount > MaxLogs {
				return Report{}, ErrInput
			}
			frameCount += len(result.Frames)
			if frameCount > MaxFrames {
				return Report{}, ErrInput
			}
			receipts = append(receipts, receipt)
			encoded, err := json.Marshal(result)
			if err != nil || len(encoded) > MaxProjectionBytes-projectionBytes {
				return Report{}, ErrInput
			}
			projectionBytes += len(encoded)
			report.Transactions = append(report.Transactions, result)
		}
		if used != block.GasUsed() || types.DeriveSha(receipts, trie.NewStackTrie(nil)) != block.ReceiptHash() {
			return Report{}, ErrInput
		}
		if engine.Finalize(chain, header, st, block.Transactions(), block.Uncles()) != nil || st.Error() != nil || header.Root != block.Root() || header.Hash() != block.Hash() {
			return Report{}, ErrInput
		}
		computed, err := st.Commit(uint64(n), g.Config.IsEIP158(header.Number))
		if err != nil || computed != block.Root() || tdb.Commit(computed, false) != nil {
			return Report{}, ErrInput
		}
		totalGas += used
		chain.add(header)
		evidence := blockEvidence(block, file)
		encoded, err := json.Marshal(evidence)
		if err != nil || len(encoded) > MaxProjectionBytes-projectionBytes {
			return Report{}, ErrInput
		}
		projectionBytes += len(encoded)
		report.Source.Blocks = append(report.Source.Blocks, evidence)
	}
	for _, input := range r.files {
		if _, _, err := r.read(input); err != nil {
			return Report{}, ErrInput
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > MaxProjectionBytes {
		return Report{}, ErrInput
	}
	return report, nil
}
