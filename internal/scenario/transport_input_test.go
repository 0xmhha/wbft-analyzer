package scenario

import (
	"strings"
	"testing"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func TestTransportSelectionKeepsAliasesAndMissingClocksExplicit(t *testing.T) {
	a, b := "0x"+strings.Repeat("1", 40), "0x"+strings.Repeat("2", 40)
	send := messages.Record{Input: "journal-a", Node: a, Run: "native", Type: "frame", Dir: "out", Peer: b, Phase: "prepare", Height: "2", Round: "0", Key: "0x" + strings.Repeat("a", 64), Write: "ok", Wall: "2020-01-01T00:00:00Z"}
	alias := send
	alias.Input, alias.Run = "wire-a", "wire"
	alias.IO = &messages.IOInterval{StartWall: "2020-01-01T00:00:00Z", EndWall: "2020-01-01T00:00:00Z", StartMono: "0", EndMono: "0"}
	receive := alias
	receive.Input, receive.Node, receive.Peer, receive.Dir = "wire-b", b, a, "in"
	receive.Write = ""
	receive.IO = &messages.IOInterval{StartWall: "2020-01-01T00:00:00.001Z", EndWall: "2020-01-01T00:00:00.001Z", StartMono: "1000000", EndMono: "1000000"}
	inputs := []MessageInput{
		{Source: Input{ID: send.Input, Kind: "journal", Node: a, SHA256: strings.Repeat("a", 64)}, Records: []messages.Record{send}},
		{Source: Input{ID: alias.Input, Kind: "frames", Node: a, SHA256: strings.Repeat("b", 64)}, Records: []messages.Record{alias}},
		{Source: Input{ID: receive.Input, Kind: "frames", Node: b, SHA256: strings.Repeat("c", 64)}, Records: []messages.Record{receive}},
	}
	all, err := selectTransportInputs(inputs, nil, []string{a, b})
	if err != nil || len(all) != 3 {
		t.Fatal(all, err)
	}
	clock := pairs.Clock{Model: "shared-host"}
	ambiguous, err := PairMessageInputsMetric(all, clock, pairs.WriteStartToReadComplete)
	if err != nil || len(ambiguous) != 1 || ambiguous[0].Status != "ambiguous" || ambiguous[0].SendCandidates != 2 {
		t.Fatal("missing-clock alias was silently removed", ambiguous, err)
	}
	selected, err := selectTransportInputs(inputs, []string{"wire-b", "wire-a"}, []string{a, b})
	if err != nil || selected[0].Source.ID != "wire-a" || inputs[0].Source.ID != "journal-a" {
		t.Fatal(selected, err)
	}
	unique, err := PairMessageInputsMetric(selected, clock, pairs.WriteStartToReadComplete)
	if err != nil || len(unique) != 1 || unique[0].Status != "valid" || unique[0].Send.Input != "wire-a" || unique[0].Receive.Input != "wire-b" {
		t.Fatal(unique, err)
	}
	for _, ids := range [][]string{{"missing"}, {"wire-a", "wire-a"}, {"journal-a", "wire-a"}, {""}, make([]string, 257)} {
		if _, err := selectTransportInputs(inputs, ids, []string{a, b}); err == nil {
			t.Fatal("invalid selection accepted", ids)
		}
	}
	if _, err := selectTransportInputs(inputs, []string{"wire-b"}, []string{a}); err == nil {
		t.Fatal("node outside fitted validator scope accepted")
	}
	inputs = append(inputs, inputs[0])
	if _, err := selectTransportInputs(inputs, []string{"wire-b"}, []string{a, b}); err == nil {
		t.Fatal("duplicate unselected identity hidden")
	}
}
