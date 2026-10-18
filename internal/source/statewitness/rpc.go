package statewitness

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	"github.com/ethereum/go-ethereum/common"
)

var ErrRPC = errors.New("execution-state request and response do not match")

type proofRequest struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

type proofResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  AccountProof    `json:"result"`
}

// VerifyRPC checks the original fixed-height request before authenticating
// its response. The authority and root must come from separately decoded
// configuration and header sources. Remote peer identity is not proved.
func VerifyRPC(request, response []byte, number *big.Int, authority common.Address, root common.Hash) (VerifiedAccount, error) {
	var req proofRequest
	var res proofResponse
	if exactJSON(request, MaxAccountBytes, &req) != nil || exactJSON(response, MaxAccountBytes, &res) != nil ||
		req.JSONRPC != "2.0" || res.JSONRPC != "2.0" || req.Method != "eth_getProof" || len(req.Params) != 3 ||
		!sameID(req.ID, res.ID) || number == nil || number.Sign() < 0 || number.BitLen() > 256 {
		return VerifiedAccount{}, ErrRPC
	}
	var address, tag string
	var keys []string
	if json.Unmarshal(req.Params[0], &address) != nil || json.Unmarshal(req.Params[1], &keys) != nil ||
		json.Unmarshal(req.Params[2], &tag) != nil || keys == nil || len(keys) > MaxStorageSlots ||
		tag != "0x"+number.Text(16) {
		return VerifiedAccount{}, ErrRPC
	}
	raw, err := fixedHex(address, 20)
	if err != nil || common.BytesToAddress(raw) != authority {
		return VerifiedAccount{}, ErrRPC
	}
	raw, err = fixedHex(res.Result.Address, 20)
	if err != nil || common.BytesToAddress(raw) != authority || len(keys) != len(res.Result.StorageProof) {
		return VerifiedAccount{}, ErrRPC
	}
	wanted := make(map[common.Hash]bool, len(keys))
	for _, key := range keys {
		slot, err := storageKey(key)
		if err != nil || wanted[slot] {
			return VerifiedAccount{}, ErrRPC
		}
		wanted[slot] = true
	}
	for _, proof := range res.Result.StorageProof {
		slot, err := storageKey(proof.Key)
		if err != nil || !wanted[slot] {
			return VerifiedAccount{}, ErrRPC
		}
		delete(wanted, slot)
	}
	if len(wanted) != 0 {
		return VerifiedAccount{}, ErrRPC
	}
	return VerifyAccount(root, res.Result)
}

func sameID(a, b json.RawMessage) bool {
	if !bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b)) {
		return false
	}
	// Preserve string and integer ID domains. Floating-point conversion would
	// conflate distinct large IDs; fractional/exponential IDs are unsupported.
	normalize := func(raw json.RawMessage) (string, bool) {
		raw = bytes.TrimSpace(raw)
		var text string
		if len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &text) == nil {
			return "string:" + text, true
		}
		n, ok := new(big.Int).SetString(string(raw), 10)
		if !ok || n.BitLen() > 256 || n.String() != string(raw) {
			return "", false
		}
		return "integer:" + n.String(), true
	}
	x, ok := normalize(a)
	y, other := normalize(b)
	return ok && other && x == y
}

func exactJSON(raw []byte, limit int, dst any) error {
	if !utf8.Valid(raw) || jsonmeta.Decode(raw, limit, true, dst) != nil || !exactFields(raw, reflect.TypeOf(dst).Elem()) {
		return ErrRPC
	}
	return nil
}

// encoding/json accepts case-insensitive field aliases even in strict mode.
// Require the declared spelling at every typed object boundary as well.
func exactFields(raw json.RawMessage, typ reflect.Type) bool {
	if typ == reflect.TypeFor[json.RawMessage]() {
		return true
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil {
			return false
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
		for key, value := range object {
			field, ok := fields[key]
			if !ok || !exactFields(value, field) {
				return false
			}
		}
	case reflect.Slice:
		// Scalar byte slices do not occur in this source contract.
		var list []json.RawMessage
		if json.Unmarshal(raw, &list) != nil {
			return false
		}
		for _, item := range list {
			if !exactFields(item, typ.Elem()) {
				return false
			}
		}
	}
	return true
}

func decimalIndex(s string) (uint64, bool) {
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil && strconv.FormatUint(n, 10) == s
}
