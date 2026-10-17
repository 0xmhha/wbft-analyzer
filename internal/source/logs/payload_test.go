package logs_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

func payloadLogFixture(t *testing.T, code codec.Code) (map[string]any, []byte) {
	t.Helper()
	scalar := make([]byte, 32)
	scalar[31] = 1
	key, err := ecdsa.PrivateKeyFromBytes(scalar)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := new(big.Int).SetString("18446744073709551617", 10)
	m := &codec.Message{Code: code, View: types.View{Sequence: types.MustHeightFromBig(n)}, Digest: types.Hash{1}}
	signing, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature, err = ecdsa.SignData(signing, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	phrase, level := "WBFT: PREPARE payload", "trace"
	if code == codec.CodeCommit {
		phrase = "WBFT: COMMIT payload"
	}
	if code == codec.CodeRoundChange {
		phrase, level = "WBFT: broadcast ROUND-CHANGE message", "info"
	}
	return map[string]any{"msg": phrase, "lvl": level, "address": ecdsa.Address(key).Hex(), "msg.source": ecdsa.Address(key).Hex(), "msg.sequence": n.String(), "msg.round": "0", "msg.code": uint64(code), "payload": "0x" + hex.EncodeToString(raw), "err": "PRIVATE_ERROR", "path": "/private/input"}, raw
}
func TestLoggedPayloadProjectionRecoversExactIdentityWithoutBytes(t *testing.T) {
	for _, code := range []codec.Code{codec.CodePrepare, codec.CodeCommit, codec.CodeRoundChange} {
		row, wire := payloadLogFixture(t, code)
		raw, _ := json.Marshal(row)
		out := logs.MessagePayload(raw)
		sum := sha256.Sum256(wire)
		if out == nil || out.Status != "decoded" || out.Height != "18446744073709551617" || out.SHA256 != hex.EncodeToString(sum[:]) || out.Signer != strings.ToLower(row["address"].(string)) {
			t.Fatal(out)
		}
		projected, _ := json.Marshal(out)
		for _, secret := range []string{hex.EncodeToString(wire), "PRIVATE_ERROR", "/private/input"} {
			if bytes.Contains(projected, []byte(secret)) {
				t.Fatal("raw input escaped")
			}
		}
	}
}
func TestLoggedPayloadProjectionRefusesContradictionsAndWrongLevels(t *testing.T) {
	for _, change := range []string{"missing", "invalid hex", "wrong code", "wrong height", "wrong round", "wrong signer", "wrong recording node", "wrong digest", "wrong level", "duplicate payload"} {
		t.Run(change, func(t *testing.T) {
			row, _ := payloadLogFixture(t, codec.CodePrepare)
			switch change {
			case "missing":
				delete(row, "payload")
			case "invalid hex":
				row["payload"] = "0xZZ"
			case "wrong code":
				row["msg.code"] = 20
			case "wrong height":
				row["msg.sequence"] = "1"
			case "wrong round":
				row["msg.round"] = "1"
			case "wrong signer":
				row["msg.source"] = "0x" + strings.Repeat("2", 40)
			case "wrong recording node":
				row["address"] = "0x" + strings.Repeat("2", 40)
			case "wrong digest":
				row["digest"] = "0x" + strings.Repeat("f", 64)
			case "wrong level":
				row["lvl"] = "info"
			}
			raw, _ := json.Marshal(row)
			if change == "duplicate payload" {
				raw = append(raw[:len(raw)-1], []byte(`,"payload":"0x00"}`)...)
			}
			out := logs.MessagePayload(raw)
			if out != nil && out.Status == "decoded" {
				t.Fatal("contradictory payload accepted", out)
			}
		})
	}
}
func TestLoggedPayloadProjectionPreservesFirstReservedPhrase(t *testing.T) {
	row, _ := payloadLogFixture(t, codec.CodePrepare)
	raw, _ := json.Marshal(row)
	raw = append(raw[:len(raw)-1], []byte(`,"msg":19}`)...)
	out := logs.MessagePayload(raw)
	if out == nil || out.Status != "decoded" {
		t.Fatal(out)
	}
}

func TestLoggedPayloadUnfilledSourceStillRequiresRecordingSigner(t *testing.T) {
	row, _ := payloadLogFixture(t, codec.CodeRoundChange)
	row["msg.source"] = "0x" + strings.Repeat("0", 40)
	raw, _ := json.Marshal(row)
	out := logs.MessagePayload(raw)
	if out == nil || out.Status != "decoded" || out.Signer != strings.ToLower(row["address"].(string)) {
		t.Fatal(out)
	}
	row["address"] = "0x" + strings.Repeat("2", 40)
	raw, _ = json.Marshal(row)
	if out = logs.MessagePayload(raw); out == nil || out.Status == "decoded" {
		t.Fatal("unknown context bypassed recording identity", out)
	}
}
