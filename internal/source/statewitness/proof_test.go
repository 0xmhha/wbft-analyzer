package statewitness

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// A single-leaf Patricia trie has an even, terminating path followed by the
// full hashed key. Constructing it independently avoids proving with the same
// helper which is under test.
func leaf(t *testing.T, key, value []byte) (common.Hash, string) {
	t.Helper()
	path := append([]byte{0x20}, key...)
	raw, err := rlp.EncodeToBytes([][]byte{path, value})
	if err != nil {
		t.Fatal(err)
	}
	return crypto.Keccak256Hash(raw), hexutil.Encode(raw)
}

func example(t *testing.T, empty bool) (common.Hash, AccountProof) {
	t.Helper()
	address := common.HexToAddress("0x01")
	key := common.HexToHash("0x01")
	storageRoot := crypto.Keccak256Hash([]byte{0x80})
	nodes, value := []string{}, "0x0"
	if !empty {
		encoded, err := rlp.EncodeToBytes([]byte{7})
		if err != nil {
			t.Fatal(err)
		}
		root, node := leaf(t, crypto.Keccak256(key[:]), encoded)
		storageRoot, nodes, value = root, []string{node}, "0x7"
	}
	code := crypto.Keccak256Hash([]byte("synthetic runtime"))
	account, err := rlp.EncodeToBytes(stateAccount{Nonce: 9, Balance: big.NewInt(5), Root: storageRoot, CodeHash: code[:]})
	if err != nil {
		t.Fatal(err)
	}
	root, node := leaf(t, crypto.Keccak256(address[:]), account)
	return root, AccountProof{Address: address.Hex(), AccountProof: []string{node}, Balance: "0x5", CodeHash: code.Hex(), Nonce: "0x9", StorageHash: storageRoot.Hex(), StorageProof: []StorageProof{{Key: key.Hex(), Value: value, Proof: nodes}}}
}

func TestAccountAndStorageProof(t *testing.T) {
	for _, empty := range []bool{false, true} {
		root, proof := example(t, empty)
		account, err := VerifyAccount(root, proof)
		if err != nil {
			t.Fatal(err)
		}
		value, ok := account.Value(common.HexToHash("0x01"))
		if !ok || account.Slots() != 1 || value == (common.Hash{}) != empty {
			t.Fatal("proven storage differs", account, value, ok)
		}
		if _, ok := account.Value(common.HexToHash("0x02")); ok {
			t.Fatal("unrequested slot became proven zero")
		}
		if account.Nonce() != 9 || account.Balance().Cmp(big.NewInt(5)) != 0 {
			t.Fatal("account metadata differs")
		}
		account.Balance().SetInt64(100)
		if account.Balance().Cmp(big.NewInt(5)) != 0 {
			t.Fatal("a returned balance mutated authenticated metadata")
		}
	}
}

func TestProvenStorageNonMembership(t *testing.T) {
	root, proof := example(t, false)
	proof.StorageProof[0].Key, proof.StorageProof[0].Value = "0x2", "0x0"
	account, err := VerifyAccount(root, proof)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := account.Value(common.HexToHash("0x02"))
	if !ok || value != (common.Hash{}) {
		t.Fatal("missing trie leaf is not a proven zero")
	}
}

func TestRejectAlteredProofsAndClaims(t *testing.T) {
	tests := map[string]func(*common.Hash, *AccountProof){
		"root":           func(root *common.Hash, _ *AccountProof) { root[0] ^= 1 },
		"address":        func(_ *common.Hash, p *AccountProof) { p.Address = common.HexToAddress("0x02").Hex() },
		"balance":        func(_ *common.Hash, p *AccountProof) { p.Balance = "0x6" },
		"nonce":          func(_ *common.Hash, p *AccountProof) { p.Nonce = "0xa" },
		"nonce overflow": func(_ *common.Hash, p *AccountProof) { p.Nonce = "0x10000000000000000" },
		"code":           func(_ *common.Hash, p *AccountProof) { p.CodeHash = common.Hash{}.Hex() },
		"storage root":   func(_ *common.Hash, p *AccountProof) { p.StorageHash = common.Hash{}.Hex() },
		"value":          func(_ *common.Hash, p *AccountProof) { p.StorageProof[0].Value = "0x8" },
		"quantity":       func(_ *common.Hash, p *AccountProof) { p.StorageProof[0].Value = "0x07" },
		"missing path":   func(_ *common.Hash, p *AccountProof) { p.StorageProof[0].Proof = []string{} },
		"nil path":       func(_ *common.Hash, p *AccountProof) { p.StorageProof[0].Proof = nil },
		"duplicate":      func(_ *common.Hash, p *AccountProof) { p.StorageProof = append(p.StorageProof, p.StorageProof[0]) },
		"alias": func(_ *common.Hash, p *AccountProof) {
			other := p.StorageProof[0]
			other.Key = "0x1"
			p.StorageProof = append(p.StorageProof, other)
		},
		"unused node": func(_ *common.Hash, p *AccountProof) { p.AccountProof = append(p.AccountProof, "0x80") },
		"repeated node": func(_ *common.Hash, p *AccountProof) {
			p.AccountProof = append(p.AccountProof, p.AccountProof[0])
		},
		"oversized node": func(_ *common.Hash, p *AccountProof) {
			p.AccountProof = []string{"0x" + strings.Repeat("00", MaxNodeBytes+1)}
		},
		"node count": func(_ *common.Hash, p *AccountProof) { p.AccountProof = make([]string, MaxProofNodes+1) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			root, proof := example(t, false)
			mutate(&root, &proof)
			if _, err := VerifyAccount(root, proof); err == nil {
				t.Fatal("altered proof or unproven metadata accepted")
			}
		})
	}
}
