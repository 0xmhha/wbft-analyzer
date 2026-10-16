package governance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
)

var ErrInvalid = errors.New("invalid bounded governance capture")

func quantity(s string, bits int) bool {
	if len(s) < 3 || len(s) > 2+(bits+3)/4 || !strings.HasPrefix(s, "0x") || len(s) > 3 && s[2] == '0' {
		return false
	}
	for _, c := range s[2:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func uint64Of(s string) (uint64, bool) {
	if !quantity(s, 64) {
		return 0, false
	}
	n, ok := new(big.Int).SetString(s[2:], 16)
	return n.Uint64(), ok
}

// Range accepts canonical uint64 hex indices, not full-height decimal strings.
func Range(from, to string) (uint64, uint64, error) {
	a, aOK := uint64Of(from)
	b, bOK := uint64Of(to)
	if !aOK || !bOK || b < a || b-a >= 1024 {
		return 0, 0, ErrInvalid
	}
	return a, b, nil
}
func fixed(s string, length int) bool {
	if len(s) != 2+length*2 || !strings.HasPrefix(s, "0x") {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}
func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func summary(raw []byte) Bytes { return Bytes{SHA256: digest(raw), Length: len(raw)} }
func hexBytes(s string) ([]byte, error) {
	if len(s) < 2 || len(s) > 2+(1<<20)*2 || !strings.HasPrefix(s, "0x") || len(s)%2 != 0 {
		return nil, ErrInvalid
	}
	v, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, ErrInvalid
	}
	return v, nil
}
func describeHex(s string) (Bytes, error) {
	v, err := hexBytes(s)
	return summary(v), err
}
func null(v json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(v), []byte("null")) }

func decode(raw json.RawMessage, dst any, nonnull ...string) error {
	if jsonmeta.Decode(raw, MaxBytes, false, dst) != nil || null(raw) || !exactKnownNames(raw, reflect.TypeOf(dst)) {
		return ErrInvalid
	}
	if len(nonnull) > 0 {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return ErrInvalid
		}
		for _, k := range nonnull {
			if len(fields[k]) == 0 || null(fields[k]) {
				return ErrInvalid
			}
		}
	}
	return nil
}

// encoding/json otherwise accepts case-insensitive aliases for known fields.
// Unknown fields may be discarded; aliases must not overwrite known metadata.
func exactKnownNames(raw json.RawMessage, typ reflect.Type) bool {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return true
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		for key := range fields {
			if strings.EqualFold(key, name) && key != name {
				return false
			}
		}
		if value, exists := fields[name]; exists && !exactKnownNames(value, f.Type) {
			return false
		}
	}
	return true
}

func hasFields(raw json.RawMessage, keys ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, key := range keys {
		if len(fields[key]) == 0 {
			return false
		}
	}
	return true
}
func addresses(values []string, required bool) ([]string, error) {
	if len(values) > 4096 || required && values == nil {
		return nil, ErrInvalid
	}
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		key := strings.ToLower(value)
		if !fixed(value, 20) || seen[key] {
			return nil, ErrInvalid
		}
		seen[key] = true
		out = append(out, key)
	}
	return out, nil
}
func modes(values map[string]string) (map[string]string, error) {
	if values == nil || len(values) > 32 {
		return nil, ErrInvalid
	}
	out := map[string]string{}
	for addr, mode := range values {
		key := strings.ToLower(addr)
		if !fixed(addr, 20) || mode != "replay" && mode != "projection-only" || out[key] != "" {
			return nil, ErrInvalid
		}
		out[key] = mode
	}
	return out, nil
}
func within(number string, from, to uint64) bool {
	n, ok := uint64Of(number)
	return ok && n >= from && n <= to
}

// recordHash preserves source context without inventing a link for legacy data.
func recordHash(value *string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	if !fixed(*value, 32) {
		return nil, ErrInvalid
	}
	normalized := strings.ToLower(*value)
	if normalized == "0x"+strings.Repeat("0", 64) {
		return nil, nil
	}
	return &normalized, nil
}
