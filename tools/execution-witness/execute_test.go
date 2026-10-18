package main

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

func syntheticTransaction(t *testing.T, collision bool, code []byte) (Transaction, *types.Receipt) {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	defer db.Close()
	backend := state.NewDatabase(db)
	defer backend.TrieDB().Close()
	st, err := state.New(types.EmptyRootHash, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	st.AddBalance(sender, uint256.NewInt(1000000000))
	target := syntheticAuthority
	config := *params.AllEthashProtocolChanges
	config.ChainID = big.NewInt(12345)
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 1000000, BaseFee: big.NewInt(0), Time: 1}
	data := &types.LegacyTx{Nonce: 0, To: &target, Gas: 100000, GasPrice: big.NewInt(1), Value: big.NewInt(0)}
	if collision {
		data.To = nil
		data.Data = []byte{0x60, 0}
		created := crypto.CreateAddress(sender, 0)
		st.SetNonce(created, 1)
	} else {
		st.SetCode(target, code)
	}
	tx, err := types.SignTx(types.NewTx(data), types.MakeSigner(&config, header.Number, header.Time), key)
	if err != nil {
		t.Fatal(err)
	}
	chain := &chainContext{config: &config, states: backend, headers: map[uint64]*types.Header{}, byHash: map[common.Hash]uint64{}, td: map[uint64]*big.Int{}}
	used := uint64(0)
	result, receipt, err := apply(context.Background(), chain, header, st, tx, 0, new(core.GasPool).AddGas(header.GasLimit), &used, params.SystemContracts{GovValidator: &params.SystemContract{Address: target, Version: "v1"}}, "0")
	if err != nil {
		t.Fatal(err)
	}
	if used != receipt.GasUsed {
		t.Fatal("gas accounting differs")
	}
	return result, receipt
}
func TestFailedCreationWithoutCallHookHasActualExecutionResult(t *testing.T) {
	result, receipt := syntheticTransaction(t, true, nil)
	if receipt.Status != types.ReceiptStatusFailed || len(result.Frames) != 1 {
		t.Fatal("creation collision not retained")
	}
	root := result.Frames[0]
	if root.Observation != "execution_result" || root.VMError != "contract_address_collision" || root.Status != "vm_error" || root.Effective || root.AccountCodeHash != "" || root.ErrorName != "" || root.Gas != "" {
		t.Fatal("unobserved call details inferred")
	}
}
func TestMatchingErrorSelectorFromUnknownCodeIsNotNamed(t *testing.T) {
	selector := crypto.Keccak256([]byte("InvalidProposal()"))[:4]
	code := append([]byte{0x63}, selector...)
	code = append(code, 0x60, 0xe0, 0x1b, 0x60, 0, 0x52, 0x60, 4, 0x60, 0, 0xfd)
	result, receipt := syntheticTransaction(t, false, code)
	root := result.Frames[0]
	if receipt.Status != types.ReceiptStatusFailed || root.VMError != "execution_reverted" || root.Return.Bytes != 4 {
		t.Fatal("synthetic revert did not execute")
	}
	if root.ABIStatus != "unknown_runtime" || root.ErrorName != "" || root.AccountCodeHash == validatorProfile.code.Hex() {
		t.Fatal("unreviewed code received a governance error name")
	}
}

func TestReceiptLogsKeepOrderWithoutPayload(t *testing.T) {
	raw := []byte("private log payload")
	topics := []common.Hash{common.HexToHash("0x01"), common.HexToHash("0x02")}
	logs, err := normalizeLogs([]*types.Log{{Address: syntheticAuthority, Topics: topics, Data: raw}, {Address: common.Address{}}})
	if err != nil || len(logs) != 2 || logs[0].Address != strings.ToLower(syntheticAuthority.Hex()) || logs[0].Topics[0] != topics[0].Hex() || logs[0].Topics[1] != topics[1].Hex() || logs[0].Data != digest(raw) || logs[1].Topics == nil || logs[1].Data != digest(nil) {
		t.Fatal("receipt log projection differs")
	}
	topics[0] = common.Hash{}
	raw[0] = 'x'
	if logs[0].Topics[0] != common.HexToHash("0x01").Hex() || logs[0].Data == digest(raw) {
		t.Fatal("projection retained mutable payload")
	}
	for _, input := range [][]*types.Log{{nil}, {{Topics: make([]common.Hash, 5)}}, make([]*types.Log, MaxTransactionLogs+1)} {
		if _, err := normalizeLogs(input); err == nil {
			t.Fatal("unbounded or invalid receipt logs accepted")
		}
	}
	empty, err := normalizeLogs(nil)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("empty logs must be explicit")
	}
}

func TestReplayRefusesExcessiveBlockGasBeforeExecution(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, gas := range []uint64{MaxBlockGas, MaxBlockGas + 1} {
		header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: gas, UncleHash: types.EmptyUncleHash}
		block := types.NewBlockWithHeader(header)
		raw, err := rlp.EncodeToBytes(block)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "block"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		reader := &sourceReader{ctx: context.Background(), root: root, files: map[string]FileInput{}}
		_, _, err = reader.block(BlockInput{Index: "1", File: FileInput{Path: "block", SHA256: digest(raw).SHA256}})
		if (err != nil) != (gas > MaxBlockGas) {
			t.Fatal("block gas boundary ignored")
		}
	}
}
