package main

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/wbft"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

var syntheticAuthority = common.HexToAddress("0x1111111111111111111111111111111111111111")

func frameForProfile() Frame {
	return Frame{Status: "reverted", To: strings.ToLower(syntheticAuthority.Hex()), AccountCodeHash: validatorProfile.code.Hex()}
}
func TestErrorNamesRequireRoleRuntimeAndCanonicalABI(t *testing.T) {
	sc := params.SystemContracts{GovValidator: &params.SystemContract{Address: syntheticAuthority, Version: "v1"}}
	payload := crypto.Keccak256([]byte("InvalidProposal()"))[:4]
	cases := []struct {
		name              string
		alter             func(*Frame, *params.SystemContracts)
		data              []byte
		status, nameValue string
	}{
		{"known", func(*Frame, *params.SystemContracts) {}, payload, "decoded_revert", "InvalidProposal"},
		{"unknown runtime", func(f *Frame, _ *params.SystemContracts) { f.AccountCodeHash = common.Hash{}.Hex() }, payload, "unknown_runtime", ""},
		{"unconfigured target", func(f *Frame, _ *params.SystemContracts) { f.To = "0x2222222222222222222222222222222222222222" }, payload, "unknown_runtime", ""},
		{"unknown version", func(_ *Frame, s *params.SystemContracts) {
			s.GovValidator = &params.SystemContract{Address: syntheticAuthority, Version: "v9"}
		}, payload, "unknown_runtime", ""},
		{"unknown selector", func(*Frame, *params.SystemContracts) {}, []byte{0xde, 0xad, 0xbe, 0xef}, "unknown_selector", ""},
		{"extra byte", func(*Frame, *params.SystemContracts) {}, append(append([]byte{}, payload...), 0), "malformed_revert", ""},
		{"short", func(*Frame, *params.SystemContracts) {}, []byte{1}, "malformed_revert", ""},
		{"empty", func(*Frame, *params.SystemContracts) {}, nil, "empty_revert", ""},
		{"not reverted", func(f *Frame, _ *params.SystemContracts) { f.Status = "succeeded" }, payload, "not_reverted", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := frameForProfile()
			copy := sc
			tc.alter(&f, &copy)
			interpret(&f, copy, false, tc.data)
			if f.ABIStatus != tc.status || f.ErrorName != tc.nameValue {
				t.Fatalf("status=%s name=%s", f.ABIStatus, f.ErrorName)
			}
		})
	}
	f := frameForProfile()
	interpret(&f, sc, true, payload)
	if f.ErrorName != "" {
		t.Fatal("creation bytes treated as runtime ABI")
	}
	f = frameForProfile()
	f.AccountCodeHash = councilProfile.code.Hex()
	sc = params.SystemContracts{GovCouncil: &params.SystemContract{Address: syntheticAuthority, Version: "v1"}}
	interpret(&f, sc, false, crypto.Keccak256([]byte("InvalidValidator()"))[:4])
	if f.ABIStatus != "unknown_selector" || f.ErrorName != "" {
		t.Fatal("validator error attributed to council code")
	}
}
func TestStandardErrorArgumentsNeverLeaveProjection(t *testing.T) {
	definition := validatorProfile.abi.Errors["Error"]
	secret := "opaque-revert-detail"
	args, err := definition.Inputs.Pack(secret)
	if err != nil {
		t.Fatal(err)
	}
	data := append(append([]byte{}, definition.ID[:4]...), args...)
	f := frameForProfile()
	f.Return = digest(data)
	interpret(&f, params.SystemContracts{GovValidator: &params.SystemContract{Address: syntheticAuthority, Version: "v1"}}, false, data)
	raw, _ := json.Marshal(f)
	if f.ErrorName != "Error" || strings.Contains(string(raw), secret) {
		t.Fatal("arbitrary revert message exposed")
	}
}
func TestTransactionAuthorityUsesParentFinalizationBoundary(t *testing.T) {
	old := &params.SystemContract{Address: syntheticAuthority, Version: "v1"}
	next := &params.SystemContract{Address: common.HexToAddress("0x2222222222222222222222222222222222222222"), Version: "v1"}
	cfg := &wbft.Config{SystemContractUpgrades: []params.Upgrade{{Block: big.NewInt(0), SystemContracts: &params.SystemContracts{GovValidator: old}}, {Block: big.NewInt(8), SystemContracts: &params.SystemContracts{GovValidator: next}}}}
	for _, tc := range []struct {
		height int64
		want   common.Address
		parent string
	}{{1, old.Address, "0"}, {8, old.Address, "7"}, {9, next.Address, "8"}} {
		sc, parent, err := transactionAuthority(cfg, &params.ChainConfig{}, big.NewInt(tc.height))
		if err != nil || sc.GovValidator.Address != tc.want || parent != tc.parent {
			t.Fatalf("wrong execution authority at %d", tc.height)
		}
	}
	if _, _, err := transactionAuthority(&wbft.Config{}, &params.ChainConfig{}, big.NewInt(1)); err == nil {
		t.Fatal("preset fallback accepted")
	}
}
func TestRevertedAncestorsRemoveChildEffects(t *testing.T) {
	c := capture{starts: 1, ends: 1, frames: []observedFrame{{parent: -1, Frame: Frame{Status: "succeeded"}}, {parent: 0, Frame: Frame{Status: "reverted"}}, {parent: 1, Frame: Frame{Status: "succeeded"}}, {parent: 0, Frame: Frame{Status: "succeeded"}}}}
	frames, err := c.projection()
	if err != nil || !frames[0].Effective || frames[1].Effective || frames[2].Effective || !frames[3].Effective {
		t.Fatal("reverted child subtree kept effects")
	}
	c.frames[0].Status = "reverted"
	frames, err = c.projection()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		if f.Effective {
			t.Fatal("reverted root kept child effects")
		}
	}
}
