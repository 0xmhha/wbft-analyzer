package statewitness

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func authorityExample(extra string) []byte {
	return []byte(`{"chainId":7,"anzeon":{"wbft":{},"systemContracts":{"govValidator":{"address":"0x0000000000000000000000000000000000001111","version":"v1"}}}` + extra + `}`)
}

func TestExactConfigBytesAndGenesisWrapper(t *testing.T) {
	raw := authorityExample("")
	sum := sha256.Sum256(raw)
	for _, input := range [][]byte{raw, append(append([]byte(`{"config":  `), raw...), []byte(`,"alloc":{}}`)...)} {
		config, err := ParseAuthorityConfig(input)
		if err != nil {
			t.Fatal(err)
		}
		address, err := config.ContractAt(big.NewInt(10))
		if err != nil || address != common.HexToAddress("0x1111") || config.ChainID != "7" || config.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("config identity or configured address differs", config, err)
		}
	}
	withNewline, err := ParseAuthorityConfig(append(raw, '\n'))
	if err != nil || withNewline.SHA256 == hex.EncodeToString(sum[:]) {
		t.Fatal("distinct config bytes silently canonicalized", err)
	}
}

func TestConfiguredAuthorityUpgradeBoundary(t *testing.T) {
	raw := authorityExample(`,"bohoBlock":10,"boho":{"systemContracts":{"govValidator":{"address":"0x0000000000000000000000000000000000002222","version":"v1"}}}`)
	config, err := ParseAuthorityConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		height int64
		want   string
	}{{9, "0x1111"}, {10, "0x2222"}, {11, "0x2222"}} {
		got, err := config.ContractAt(big.NewInt(tc.height))
		if err != nil || got != common.HexToAddress(tc.want) {
			t.Fatal("upgrade boundary differs", tc.height, got, err)
		}
	}
	wide := "340282366920938463463374607431768211456"
	config, err = ParseAuthorityConfig([]byte(strings.ReplaceAll(string(raw), `"bohoBlock":10`, `"bohoBlock":`+wide)))
	if err != nil {
		t.Fatal(err)
	}
	at, _ := new(big.Int).SetString(wide, 10)
	got, err := config.ContractAt(at)
	if err != nil || got != common.HexToAddress("0x2222") {
		t.Fatal("wide activation was truncated", got, err)
	}
}

func TestPartialOrInactiveUpgradeRetainsAuthority(t *testing.T) {
	for _, extra := range []string{
		`,"bohoBlock":10,"boho":{"systemContracts":{"govMinter":{"address":"0x0000000000000000000000000000000000002222","version":"v2"}}}`,
		`,"bohoBlock":10,"boho":{"systemContracts":{"govValidator":null}}`,
		`,"bohoBlock":null,"boho":{"systemContracts":{"govValidator":{"address":"0x0000000000000000000000000000000000002222","version":"v1"}}}`,
	} {
		config, err := ParseAuthorityConfig(authorityExample(extra))
		if err != nil {
			t.Fatal(err)
		}
		got, err := config.ContractAt(big.NewInt(20))
		if err != nil || got != common.HexToAddress("0x1111") {
			t.Fatal("partial or inactive upgrade erased configured authority", err)
		}
	}
}

func TestUnknownAuthorityVersionRemainsUnavailable(t *testing.T) {
	raw := authorityExample(`,"bohoBlock":10,"boho":{"systemContracts":{"govValidator":{"address":"0x0000000000000000000000000000000000002222","version":"future"}}}`)
	config, err := ParseAuthorityConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.ContractAt(big.NewInt(9)); err != nil {
		t.Fatal("future unsupported code invalidated the prior configured era", err)
	}
	if _, err := config.ContractAt(big.NewInt(10)); err == nil {
		t.Fatal("unknown activated version became a supported layout")
	}
}

func TestRejectAmbiguousOrMalformedAuthorityConfig(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`null`),
		[]byte(`{"chainId":7,"anzeon":{"wbft":{}}}`),
		authorityExample(`,"bohoBlock":-1`),
		authorityExample(`,"bohoBlock":1.5`),
		authorityExample(`,"boho":"invalid"`),
		authorityExample(`,"bohoBlock":null,"boho":{"systemContracts":[]}`),
		authorityExample(`,"boho":{"systemContracts":{"govValidator":{"address":1,"version":"v1"}}}`),
		authorityExample(`,"systemContractUpgrades":[]`),
		[]byte(strings.Replace(string(authorityExample("")), `"version":"v1"`, `"version":"v1","Version":"v1"`, 1)),
		[]byte(strings.Replace(string(authorityExample("")), `"chainId":7`, `"chainId":7,"chainId":8`, 1)),
		[]byte(`{"config":` + string(authorityExample("")) + `,"Config":` + string(authorityExample("")) + `}`),
	} {
		if _, err := ParseAuthorityConfig(raw); err == nil {
			t.Fatal("ambiguous or malformed configured authority accepted")
		}
	}
	config, err := ParseAuthorityConfig(authorityExample(""))
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []*big.Int{nil, big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 256)} {
		if _, err := config.ContractAt(at); err == nil {
			t.Fatal("invalid authority lookup height accepted")
		}
	}
}
