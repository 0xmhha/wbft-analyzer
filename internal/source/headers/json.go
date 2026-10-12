package headers

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// JSONHeader is the consensus header projection of eth_getBlockByNumber.
// Quantity conversion uses geth's strict JSON quantities; consensus decoding
// and hashing remain in wbft/codec.
type JSONHeader struct {
	Hash             types.Hash      `json:"hash"`
	ParentHash       types.Hash      `json:"parentHash"`
	UncleHash        types.Hash      `json:"sha3Uncles"`
	Coinbase         types.Address   `json:"miner"`
	Root             types.Hash      `json:"stateRoot"`
	TxHash           types.Hash      `json:"transactionsRoot"`
	ReceiptHash      types.Hash      `json:"receiptsRoot"`
	Bloom            hexutil.Bytes   `json:"logsBloom"`
	Difficulty       *hexutil.Big    `json:"difficulty"`
	Number           *hexutil.Big    `json:"number"`
	GasLimit         *hexutil.Uint64 `json:"gasLimit"`
	GasUsed          *hexutil.Uint64 `json:"gasUsed"`
	Time             *hexutil.Uint64 `json:"timestamp"`
	Extra            hexutil.Bytes   `json:"extraData"`
	MixDigest        types.Hash      `json:"mixHash"`
	Nonce            hexutil.Bytes   `json:"nonce"`
	BaseFee          *hexutil.Big    `json:"baseFeePerGas"`
	WithdrawalsHash  *types.Hash     `json:"withdrawalsRoot"`
	BlobGasUsed      *hexutil.Uint64 `json:"blobGasUsed"`
	ExcessBlobGas    *hexutil.Uint64 `json:"excessBlobGas"`
	ParentBeaconRoot *types.Hash     `json:"parentBeaconBlockRoot"`
}

func DecodeJSON(raw []byte) (*types.Header, error) {
	var r *JSONHeader
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("header not found")
	}
	if r.Number == nil || r.Difficulty == nil || r.GasLimit == nil || r.GasUsed == nil || r.Time == nil || len(r.Bloom) != 256 || len(r.Nonce) != 8 || r.Extra == nil {
		return nil, errors.New("header missing required fields")
	}
	n, err := types.HeightFromBig(r.Number.ToInt())
	if err != nil {
		return nil, err
	}
	h := &types.Header{ParentHash: r.ParentHash, UncleHash: r.UncleHash, Coinbase: r.Coinbase, Root: r.Root, TxHash: r.TxHash, ReceiptHash: r.ReceiptHash, Difficulty: r.Difficulty.ToInt(), Number: n, GasLimit: uint64(*r.GasLimit), GasUsed: uint64(*r.GasUsed), Time: uint64(*r.Time), Extra: r.Extra, MixDigest: r.MixDigest, WithdrawalsHash: r.WithdrawalsHash, ParentBeaconRoot: r.ParentBeaconRoot}
	copy(h.Bloom[:], r.Bloom)
	copy(h.Nonce[:], r.Nonce)
	if r.BaseFee != nil {
		h.BaseFee = r.BaseFee.ToInt()
	}
	if r.BlobGasUsed != nil {
		v := uint64(*r.BlobGasUsed)
		h.BlobGasUsed = &v
	}
	if r.ExcessBlobGas != nil {
		v := uint64(*r.ExcessBlobGas)
		h.ExcessBlobGas = &v
	}
	if codec.BlockHash(h) != r.Hash {
		return nil, fmt.Errorf("header hash differs from RPC: %s", r.Hash.Hex())
	}
	return h, nil
}
