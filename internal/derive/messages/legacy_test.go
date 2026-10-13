package messages

import (
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

func legacyFixture() ([]logs.Event, []logs.Event, logs.LegacyAssociation) {
	addr := "0x" + strings.Repeat("1", 40)
	d := logs.LegacyAssociation{Address: addr, Input: "legacy", NativeInput: "native", SHA256: strings.Repeat("a", 64), NativeSHA256: strings.Repeat("b", 64), From: "2020-01-01T00:00:00Z", To: "2020-01-01T00:00:10Z"}
	legacy := []logs.Event{{Input: "legacy", Node: "legacy-node", Line: 1, Run: "1", Wall: "2020-01-01T00:00:01Z", Record: event.Record{Src: "log", Kind: event.EngineStart, Fields: map[string]any{"address": addr}}}}
	native := []logs.Event{}
	for i, h := range []string{"1", "18446744073709551615"} {
		hash := "0x" + strings.Repeat(string(rune('a'+i)), 64)
		fields := map[string]any{"number": h, "hash": hash}
		legacy = append(legacy, logs.Event{Input: "legacy", Node: "legacy-node", Line: int64(i + 2), Run: "1", Wall: "2020-01-01T00:00:02Z", Record: event.Record{Src: "log", Kind: event.NewHead, Fields: fields}})
		native = append(native, logs.Event{Input: "native", Node: "native-node", Line: int64(i + 1), Run: "writer", Wall: "2020-01-01T00:00:02Z", Record: event.Record{Src: "event", Kind: event.NewHead, Fields: fields}})
	}
	return legacy, native, d
}
func TestDeclaredLegacyAssociationRetainsOriginalNamespaceAndGrade(t *testing.T) {
	a, b, d := legacyFixture()
	selected, proof, e := DeclaredLegacyEvents(a, b, []logs.LegacyAssociation{d})
	if e != nil || len(selected) != 3 || len(proof) != 1 || proof[0].Status != "declared_head_anchors" || proof[0].HeadAnchors != 2 || proof[0].Anchors[1].Height != "18446744073709551615" {
		t.Fatal(selected, proof, e)
	}
	if selected[0].Run != "1" || proof[0].Anchors[0].Legacy.Kind != "log" || proof[0].Anchors[0].Native.Kind != "event" {
		t.Fatal("source evidence upgraded or rewritten", proof)
	}
}
func TestDeclaredLegacyAssociationRefusesConflictsAndInsufficientEvidence(t *testing.T) {
	for _, change := range []string{"wrong_node", "wrong_head", "repeated_head", "no_native", "other_window"} {
		t.Run(change, func(t *testing.T) {
			a, b, d := legacyFixture()
			switch change {
			case "wrong_node":
				d.Address = "0x" + strings.Repeat("2", 40)
			case "wrong_head":
				b[0].Record.Fields = map[string]any{"number": "1", "hash": "0x" + strings.Repeat("c", 64)}
			case "repeated_head":
				a = append(a, a[1])
			case "no_native":
				b = nil
			case "other_window":
				d.From = "2020-01-02T00:00:00Z"
				d.To = "2020-01-02T00:00:10Z"
			}
			if _, _, e := DeclaredLegacyEvents(a, b, []logs.LegacyAssociation{d}); e == nil {
				t.Fatal("unsupported declaration accepted")
			}
		})
	}
}

func TestLegacyWindowExclusionsRemainOriginalMessageIssues(t *testing.T) {
	a, _, _ := legacyFixture()
	outside := a[0]
	outside.Line = 99
	outside.Record.Kind = event.Send
	outside.Wall = "2020-01-02T00:00:00Z"
	_, issues := UnassociatedEvidence(nil, append(a, outside), nil, a)
	if len(issues) != 1 || issues[0].Source.Ordinal != 99 {
		t.Fatal("same-run event outside declared scope disappeared", issues)
	}
}

func TestLegacyExtraSealPairsProcessingAndPreservesRetries(t *testing.T) {
	for _, phase := range []string{"PREPARE", "COMMIT"} {
		t.Run(phase, func(t *testing.T) {
			received := logs.Event{Input: "legacy", Node: "b", Run: "legacy-run", Line: 2, Wall: "2020-01-01T00:00:01Z", Record: event.Record{Src: "log", Kind: event.ExtraSeal, Fields: map[string]any{"phase": phase, "source": "a", "msg.sequence": "1", "msg.round": "0"}}}
			anchor := logs.Event{Input: "native", Node: "a", Run: "writer", Record: event.Record{Src: "event", Kind: event.NewHead}}
			send := endpoint("send", "a", "b", "1", "bytes", 0)
			send.Phase, send.Author, send.Source.Kind = phase, "a", "message"
			projected := ProjectEvents([]logs.Event{anchor, received})
			pairs := PairEndpoints(MixEndpoints(append(projected.Endpoints, send)), Clock{Model: "shared-host"})
			if len(pairs) != 1 || pairs[0].Status != "valid" || pairs[0].Strength != "key" || pairs[0].Metric != "propagation_processing" || pairs[0].Receive.Kind != "log" {
				t.Fatal("extra seal was lost or upgraded to wire proof", projected, pairs)
			}
			pairs = PairEndpoints(MixEndpoints(append(projected.Endpoints, send, send)), Clock{Model: "shared-host"})
			if len(pairs) != 1 || pairs[0].Status != "ambiguous" || pairs[0].Seconds != nil {
				t.Fatal("repeated sends were silently collapsed", pairs)
			}
			received.Record.Src = "event"
			if p := ProjectEvents([]logs.Event{anchor, received}); len(p.Endpoints) != 0 {
				t.Fatal("native extra seal double-counted as outcome", p)
			}
			received.Record.Src = "log"
			_, excluded := UnassociatedEvidence(nil, []logs.Event{received}, nil, nil)
			if len(excluded) != 1 || excluded[0].Source.Ordinal != 2 {
				t.Fatal("excluded extra-seal source disappeared", excluded)
			}
		})
	}
}
