package logs_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/codec"
)

func TestSelectLoggedPayloadBindsEveryProjectedField(t *testing.T) {
	row, wire := payloadLogFixture(t, codec.CodePrepare)
	raw, _ := json.Marshal(row)
	witness := logs.MessagePayload(raw)
	if witness == nil {
		t.Fatal("fixture unavailable")
	}
	got, code, err := logs.SelectMessagePayload(raw, *witness)
	if err != nil || code != 0x13 || !bytes.Equal(got, wire) {
		t.Fatal(code, err)
	}
	for _, change := range []func(*logs.PayloadWitness){
		func(w *logs.PayloadWitness) { w.SHA256 = strings.Repeat("f", 64) },
		func(w *logs.PayloadWitness) { w.Signer = "0x" + strings.Repeat("2", 40) },
		func(w *logs.PayloadWitness) { w.Height = "1" },
		func(w *logs.PayloadWitness) { w.Round = "1" },
		func(w *logs.PayloadWitness) { w.Status = "missing" },
		func(w *logs.PayloadWitness) { w.Phase = "COMMIT" },
	} {
		foreign := *witness
		change(&foreign)
		if data, _, err := logs.SelectMessagePayload(raw, foreign); err == nil || data != nil {
			t.Fatal("foreign witness exposed payload")
		}
	}
	row["lvl"] = "info"
	raw, _ = json.Marshal(row)
	if data, _, err := logs.SelectMessagePayload(raw, *witness); err == nil || data != nil {
		t.Fatal("non-payload source exposed bytes")
	}
}

func TestRoundHeadRequiresExplicitPinnedPhraseAndCompleteContext(t *testing.T) {
	row := map[string]any{"msg": "WBFT: initialize new round", "lvl": "debug", "address": "0x" + strings.Repeat("1", 40), "lastProposal.hash": "0x" + strings.Repeat("2", 64), "lastProposal.number": "18446744073709551615", "target.round": "18446744073709551617", "path": "/private/context"}
	raw, _ := json.Marshal(row)
	w := logs.RoundHead(raw)
	if w == nil || w.LoggedNumber != "18446744073709551615" || w.RequestedRound != "18446744073709551617" {
		t.Fatal(w)
	}
	encoded, _ := json.Marshal(w)
	if bytes.Contains(encoded, []byte("/private/context")) {
		t.Fatal("arbitrary source context escaped")
	}
	for _, key := range []string{"address", "lastProposal.hash", "lastProposal.number", "target.round", "msg", "lvl"} {
		bad := map[string]any{}
		for k, v := range row {
			bad[k] = v
		}
		bad[key] = "unavailable"
		raw, _ := json.Marshal(bad)
		if logs.RoundHead(raw) != nil {
			t.Fatal("head was inferred without context", key)
		}
	}
	row["lastProposal.number"] = "18446744073709551616"
	raw, _ = json.Marshal(row)
	if logs.RoundHead(raw) != nil {
		t.Fatal("printed Uint64 field accepted an invented full-width number")
	}
}
