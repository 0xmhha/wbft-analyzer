// Package statewitness verifies execution-state evidence independently of RPC
// result labels. A valid Merkle proof does not authenticate a remote node or
// establish which contract supplies a network's consensus authority.
package statewitness

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

const (
	MaxProofNodes   = 128
	MaxNodeBytes    = 64 << 10
	MaxProofBytes   = 1 << 20
	MaxAccountBytes = 16 << 20
	MaxStorageSlots = 32768
)

var ErrProof = errors.New("invalid execution-state proof")

// AccountProof is the bounded result of eth_getProof. Values are checked
// against decoded trie leaves, never used in place of a missing leaf.
type AccountProof struct {
	Address      string         `json:"address"`
	AccountProof []string       `json:"accountProof"`
	Balance      string         `json:"balance"`
	CodeHash     string         `json:"codeHash"`
	Nonce        string         `json:"nonce"`
	StorageHash  string         `json:"storageHash"`
	StorageProof []StorageProof `json:"storageProof"`
}

type StorageProof struct {
	Key   string   `json:"key"`
	Value string   `json:"value"`
	Proof []string `json:"proof"`
}

type VerifiedAccount struct {
	stateRoot   common.Hash
	address     common.Address
	storageRoot common.Hash
	codeHash    common.Hash
	nonce       uint64
	balance     *big.Int
	values      map[common.Hash]common.Hash
}

func (a VerifiedAccount) Address() common.Address  { return a.address }
func (a VerifiedAccount) StateRoot() common.Hash   { return a.stateRoot }
func (a VerifiedAccount) StorageRoot() common.Hash { return a.storageRoot }
func (a VerifiedAccount) CodeHash() common.Hash    { return a.codeHash }
func (a VerifiedAccount) Nonce() uint64            { return a.nonce }

func (a VerifiedAccount) Balance() *big.Int {
	if a.balance == nil {
		return nil
	}
	return new(big.Int).Set(a.balance)
}

// Value distinguishes a proven zero, including trie non-membership, from a
// slot for which no proof was supplied.
func (a VerifiedAccount) Value(slot common.Hash) (common.Hash, bool) {
	v, ok := a.values[slot]
	return v, ok
}

func (a VerifiedAccount) Slots() int { return len(a.values) }

type stateAccount struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash
	CodeHash []byte
}

// VerifyAccount checks all supplied account and storage metadata under the
// given state root. Binding that root to an independently imported canonical
// WBFT header is a separate, mandatory step at ingestion.
func VerifyAccount(root common.Hash, p AccountProof) (VerifiedAccount, error) {
	var out VerifiedAccount
	address, err := fixedHex(p.Address, 20)
	if err != nil || len(p.StorageProof) > MaxStorageSlots || p.StorageProof == nil {
		return out, ErrProof
	}
	budget := len(p.Address) + len(p.Balance) + len(p.CodeHash) + len(p.Nonce) + len(p.StorageHash)
	for _, node := range p.AccountProof {
		budget += len(node)
		if budget > MaxAccountBytes {
			return out, ErrProof
		}
	}
	for _, slot := range p.StorageProof {
		budget += len(slot.Key) + len(slot.Value)
		if len(slot.Proof) > MaxProofNodes || budget > MaxAccountBytes {
			return out, ErrProof
		}
		for _, node := range slot.Proof {
			budget += len(node)
			if budget > MaxAccountBytes {
				return out, ErrProof
			}
		}
	}
	encoded, err := verifyPath(root, crypto.Keccak256(address), p.AccountProof)
	if err != nil || len(encoded) == 0 {
		return out, ErrProof
	}
	var account stateAccount
	if rlp.DecodeBytes(encoded, &account) != nil || account.Balance == nil || account.Balance.BitLen() > 256 || len(account.CodeHash) != 32 {
		return out, ErrProof
	}
	balance, e1 := quantity(p.Balance, 256)
	nonce, e2 := quantity(p.Nonce, 64)
	storageRoot, e3 := fixedHex(p.StorageHash, 32)
	codeHash, e4 := fixedHex(p.CodeHash, 32)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || balance.Cmp(account.Balance) != 0 || nonce.Uint64() != account.Nonce || !bytes.Equal(storageRoot, account.Root[:]) || !bytes.Equal(codeHash, account.CodeHash) {
		return out, ErrProof
	}
	out = VerifiedAccount{stateRoot: root, address: common.BytesToAddress(address), storageRoot: account.Root, codeHash: common.BytesToHash(account.CodeHash), nonce: account.Nonce, balance: new(big.Int).Set(account.Balance), values: map[common.Hash]common.Hash{}}
	for _, slot := range p.StorageProof {
		key, err := storageKey(slot.Key)
		if err != nil {
			return VerifiedAccount{}, ErrProof
		}
		if _, exists := out.values[key]; exists {
			return VerifiedAccount{}, ErrProof
		}
		expected, err := quantity(slot.Value, 256)
		if err != nil {
			return VerifiedAccount{}, ErrProof
		}
		raw, err := verifyPath(account.Root, crypto.Keccak256(key[:]), slot.Proof)
		if err != nil {
			return VerifiedAccount{}, ErrProof
		}
		var value []byte
		if len(raw) > 0 && rlp.DecodeBytes(raw, &value) != nil {
			return VerifiedAccount{}, ErrProof
		}
		// State trie integers are minimal big-endian bytes. Zero is absence;
		// a present empty integer or leading zero is not a canonical slot.
		if len(value) > 32 || len(raw) > 0 && (len(value) == 0 || value[0] == 0) || new(big.Int).SetBytes(value).Cmp(expected) != 0 {
			return VerifiedAccount{}, ErrProof
		}
		out.values[key] = common.BytesToHash(value)
	}
	return out, nil
}

type proofNodes struct {
	nodes map[string][]byte
	read  map[string]bool
}

func (p *proofNodes) Has(key []byte) (bool, error) {
	_, ok := p.nodes[string(key)]
	return ok, nil
}

func (p *proofNodes) Get(key []byte) ([]byte, error) {
	v, ok := p.nodes[string(key)]
	if !ok {
		return nil, ErrProof
	}
	p.read[string(key)] = true
	return v, nil
}

func verifyPath(root common.Hash, key []byte, proof []string) ([]byte, error) {
	if proof == nil || len(proof) > MaxProofNodes {
		return nil, ErrProof
	}
	// An empty trie has one known commitment and needs no proof nodes.
	if root == crypto.Keccak256Hash([]byte{0x80}) {
		if len(proof) != 0 {
			return nil, ErrProof
		}
		return nil, nil
	}
	db := &proofNodes{nodes: map[string][]byte{}, read: map[string]bool{}}
	total := 0
	for _, text := range proof {
		if len(text) > 2+2*MaxNodeBytes {
			return nil, ErrProof
		}
		raw, err := hexutil.Decode(text)
		if err != nil || len(raw) == 0 {
			return nil, ErrProof
		}
		total += len(raw)
		if total > MaxProofBytes {
			return nil, ErrProof
		}
		hash := string(crypto.Keccak256(raw))
		if _, exists := db.nodes[hash]; exists {
			return nil, ErrProof
		}
		db.nodes[hash] = raw
	}
	value, err := trie.VerifyProof(root, key, db)
	if err != nil || len(db.read) != len(db.nodes) {
		return nil, ErrProof
	}
	return value, nil
}

func fixedHex(value string, size int) ([]byte, error) {
	if len(value) != 2+2*size || !strings.HasPrefix(value, "0x") {
		return nil, ErrProof
	}
	decoded, err := hex.DecodeString(value[2:])
	if err != nil {
		return nil, ErrProof
	}
	return decoded, nil
}

func quantity(value string, bits int) (*big.Int, error) {
	n, err := hexutil.DecodeBig(value)
	if err != nil || n.BitLen() > bits {
		return nil, ErrProof
	}
	return n, nil
}

func storageKey(value string) (common.Hash, error) {
	if len(value) == 66 {
		raw, err := fixedHex(value, 32)
		return common.BytesToHash(raw), err
	}
	n, err := quantity(value, 256)
	if err != nil {
		return common.Hash{}, ErrProof
	}
	return common.BigToHash(n), nil
}
