package governance

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestContractMetadataPreservesExactArgumentsAndSummarizesBytes(t *testing.T) {
	// Build independent EVM calls from a small contract ABI rather than the
	// reader's method table. The reader must not infer a proposal from logs.
	contract, err := abi.JSON(strings.NewReader(`[
		{"type":"function","name":"approveProposal","inputs":[{"name":"id","type":"uint256"}]},
		{"type":"function","name":"proposeAddMember","inputs":[{"name":"who","type":"address"},{"name":"quorum","type":"uint32"}]},
		{"type":"function","name":"proposeAddBlacklistBatch","inputs":[{"name":"who","type":"address[]"}]},
		{"type":"function","name":"configureValidator","inputs":[{"name":"who","type":"address"},{"name":"key","type":"bytes"},{"name":"proof","type":"bytes"}]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	wide, _ := new(big.Int).SetString("100000000000000000000000000000000000000000000000001", 16)
	for _, tc := range []struct {
		name  string
		args  []any
		check func(ContractCall) bool
	}{
		{"approveProposal", []any{wide}, func(v ContractCall) bool { return len(v.Arguments) == 1 && v.Arguments[0].Value == "0x"+wide.Text(16) }},
		{"proposeAddMember", []any{common.HexToAddress(testAddr), uint32(3)}, func(v ContractCall) bool {
			return len(v.Arguments) == 2 && v.Arguments[0].Value == testAddr && v.Arguments[1].Value == "0x3"
		}},
		{"proposeAddBlacklistBatch", []any{[]common.Address{common.HexToAddress(testAddr)}}, func(v ContractCall) bool {
			return len(v.Arguments) == 1 && len(v.Arguments[0].Values) == 1 && v.Arguments[0].Values[0] == testAddr
		}},
		{"configureValidator", []any{common.HexToAddress(testAddr), []byte("private-key-metadata"), []byte("private-proof-metadata")}, func(v ContractCall) bool {
			return len(v.Arguments) == 3 && v.Arguments[1].Bytes != nil && v.Arguments[1].Bytes.SHA256 == digest([]byte("private-key-metadata"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, err := contract.Pack(tc.name, tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			got := contractCall(input)
			if got.Status != "decoded" || !tc.check(got) {
				t.Fatal(got)
			}
			if strings.Contains(string(raw(got)), "private-") {
				t.Fatal("opaque ABI bytes retained")
			}
			for _, bad := range [][]byte{input[:len(input)-1], append(append([]byte{}, input...), 0)} {
				if value := contractCall(bad); value.Status != "malformed" || len(value.Arguments) != 0 {
					t.Fatal(value)
				}
			}
		})
	}
	for _, input := range [][]byte{nil, {1, 2, 3}, crypto.Keccak256([]byte("unknownPrivateMethod()"))[:4]} {
		if v := contractCall(input); v.Status != "unknown" || v.Signature != "" || len(v.Arguments) != 0 {
			t.Fatal(v)
		}
	}
	if status, name := outcome("NotAMember"); status != "revert" || name != "NotAMember" {
		t.Fatal(status, name)
	}
	if status, name := outcome("private-result-label"); status != "unknown" || name != "" {
		t.Fatal(status, name)
	}
}

func TestNoncanonicalABIArgumentsCannotBecomeTrustedLabels(t *testing.T) {
	selector := crypto.Keccak256([]byte("proposeAddMember(address,uint32)"))[:4]
	input := append(append([]byte{}, selector...), make([]byte, 64)...)
	input[4] = 1 // nonzero high address padding
	if value := contractCall(input); value.Status != "malformed" {
		t.Fatal(hex.EncodeToString(input), value)
	}
	input[4] = 0
	input[36] = 1 // uint32 overflow
	if value := contractCall(input); value.Status != "malformed" {
		t.Fatal(value)
	}
}
