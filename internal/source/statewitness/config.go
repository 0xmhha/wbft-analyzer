package statewitness

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	"github.com/0xmhha/wbft/types"
	"github.com/ethereum/go-ethereum/common"
)

const MaxConfigBytes = 16 << 20

var ErrConfig = errors.New("unsupported execution-state authority configuration")

type AuthorityConfig struct {
	ChainID string
	SHA256  string
	initial configuredContract
	upgrade *configuredContract
	from    *big.Int
}

type configuredContract struct {
	address common.Address
	version string
}

// ParseAuthorityConfig uses the same config RawMessage bytes as ingest range.
// A matching hash is still a configured trust input, not an on-chain proof of
// the chain ID or its authority mode.
func ParseAuthorityConfig(raw []byte) (AuthorityConfig, error) {
	var out AuthorityConfig
	root, err := configObject(raw)
	if err != nil {
		return out, ErrConfig
	}
	config, present, err := field(root, "config")
	if err != nil {
		return out, ErrConfig
	}
	if present {
		raw = config
		root, err = configObject(raw)
		if err != nil {
			return out, ErrConfig
		}
	}
	parsed, err := types.ParseChainConfig(raw)
	if err != nil || parsed.ChainID == nil || parsed.ChainID.Sign() < 0 || parsed.ChainID.BitLen() > 512 {
		return out, ErrConfig
	}
	sum := sha256.Sum256(raw)
	out.ChainID, out.SHA256 = parsed.ChainID.String(), hex.EncodeToString(sum[:])
	anzeon, exists, err := field(root, "anzeon")
	if err != nil || !exists {
		return AuthorityConfig{}, ErrConfig
	}
	base, err := configObject(anzeon)
	if err != nil {
		return AuthorityConfig{}, ErrConfig
	}
	contract, exists, err := validatorContract(base)
	if err != nil || !exists {
		return AuthorityConfig{}, ErrConfig
	}
	out.initial = contract
	// This profile recognizes the registered contract upgrade in this chain
	// configuration version. Unknown registries cannot silently use genesis.
	if _, exists, err := field(root, "systemContractUpgrades"); err != nil || exists {
		return AuthorityConfig{}, ErrConfig
	}
	boho, exists, err := field(root, "boho")
	if err != nil {
		return AuthorityConfig{}, ErrConfig
	}
	var replacement *configuredContract
	if exists && !nullConfig(boho) {
		upgrade, err := configObject(boho)
		if err != nil {
			return AuthorityConfig{}, ErrConfig
		}
		contract, exists, err = validatorContract(upgrade)
		if err != nil {
			return AuthorityConfig{}, ErrConfig
		}
		if exists {
			replacement = &contract
		}
	}
	// Invalid registered fields remain invalid even when an upgrade has no
	// activation height. Absence of activation only changes effective state.
	activation, exists, err := field(root, "bohoBlock")
	if err != nil {
		return AuthorityConfig{}, ErrConfig
	}
	if !exists || nullConfig(activation) {
		return out, nil
	}
	var at big.Int
	if json.Unmarshal(activation, &at) != nil || at.Sign() < 0 || at.BitLen() > 256 {
		return AuthorityConfig{}, ErrConfig
	}
	if replacement != nil {
		out.upgrade, out.from = replacement, new(big.Int).Set(&at)
	}
	return out, nil
}

func (c AuthorityConfig) ContractAt(number *big.Int) (common.Address, error) {
	if number == nil || number.Sign() < 0 || number.BitLen() > 256 {
		return common.Address{}, ErrConfig
	}
	contract := c.initial
	if c.upgrade != nil && c.from != nil && number.Cmp(c.from) >= 0 {
		contract = *c.upgrade
	}
	if contract.address == (common.Address{}) || contract.version != "v1" {
		return common.Address{}, ErrConfig
	}
	return contract.address, nil
}

func validatorContract(parent map[string]json.RawMessage) (configuredContract, bool, error) {
	var out configuredContract
	raw, exists, err := field(parent, "systemContracts")
	if err != nil || !exists || nullConfig(raw) {
		return out, false, err
	}
	contracts, err := configObject(raw)
	if err != nil {
		return out, false, ErrConfig
	}
	raw, exists, err = field(contracts, "govValidator")
	if err != nil || !exists || nullConfig(raw) {
		return out, false, err
	}
	object, err := configObject(raw)
	if err != nil {
		return out, false, ErrConfig
	}
	address, exists, err := field(object, "address")
	if err != nil || !exists {
		return out, false, ErrConfig
	}
	var value string
	if json.Unmarshal(address, &value) != nil {
		return out, false, ErrConfig
	}
	decoded, err := fixedHex(value, 20)
	if err != nil {
		return out, false, ErrConfig
	}
	version, exists, err := field(object, "version")
	if err != nil || !exists || json.Unmarshal(version, &out.version) != nil || out.version == "" {
		return out, false, ErrConfig
	}
	out.address = common.BytesToAddress(decoded)
	return out, true, nil
}

func configObject(raw []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if jsonmeta.Decode(raw, MaxConfigBytes, false, &object) != nil || object == nil {
		return nil, ErrConfig
	}
	return object, nil
}

func nullConfig(raw []byte) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// The node's JSON decoder accepts case variants. Reject multiple spellings
// rather than letting their order choose an authority for a verified witness.
func field(object map[string]json.RawMessage, name string) (json.RawMessage, bool, error) {
	var found json.RawMessage
	for key, raw := range object {
		if strings.EqualFold(key, name) {
			if found != nil {
				return nil, false, ErrConfig
			}
			found = raw
		}
	}
	return found, found != nil, nil
}
