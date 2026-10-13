package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
)

func TestMixedLegacyRequiresPinnedDeclarationAndInvalidatesAfterChange(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	a := "0x" + strings.Repeat("1", 40)
	legacy := "0x" + strings.Repeat("2", 40)
	hash := "0x" + strings.Repeat("a", 64)
	mono := "1"
	wall := "2020-01-01T00:00:02Z"
	key := "0x" + strings.Repeat("b", 64)
	network := NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}
	m, release, e := s.BeginMessages(ctx, network, "journal", json.RawMessage(`{"clock":{"model":"shared-host"}}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	declaration := logs.LegacyAssociation{Address: legacy, Input: "legacy", SHA256: strings.Repeat("d", 64), NativeInput: "native", NativeSHA256: strings.Repeat("c", 64), From: "2020-01-01T00:00:00Z", To: "2020-01-01T00:00:10Z"}
	meta, _ := json.Marshal(map[string]any{"clock": "shared-host", "legacy_associations": []logs.LegacyAssociation{declaration}})
	r, release, e := s.BeginRun(ctx, network, "mixed-events", meta)
	if e != nil {
		t.Fatal(e)
	}
	release()
	if e = s.PutMessageInput(ctx, m.ID, source.Summary{ID: "journal", Node: a, Kind: "journal"}); e != nil {
		t.Fatal(e)
	}
	records := []source.Record{{Input: "journal", File: "00000000000000000000.wal", Ordinal: 1, Seq: "1", Node: a, Run: "writer", Type: "frame", Dir: "out", Peer: legacy, Signer: a, Phase: "PREPARE", Height: "1", Round: "0", Key: key, Decode: "decoded", Wall: wall, Mono: &mono, Write: "ok"}, {Input: "journal", File: "00000000000000000000.wal", Ordinal: 2, Seq: "2", Node: a, Run: "writer", Type: "outcome", Step: "2", Phase: "PREPARE", Key: key, Outcome: "ACCEPT"}, {Input: "journal", File: "00000000000000000000.wal", Ordinal: 3, Seq: "3", Node: a, Run: "writer", Type: "step", Step: "2", EngineRun: "1", Wall: wall, Mono: &mono}}
	if e = s.PutMessageRecords(ctx, m.ID, records, 3); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, m.ID, 3, ""); e != nil {
		t.Fatal(e)
	}
	for _, in := range []logs.InputSummary{{ID: "native", Node: a, Kind: "events", Profile: "wbft@events-v1", ProfileSHA256: strings.Repeat("e", 64), SHA256: declaration.NativeSHA256}, {ID: "legacy", Node: legacy, Kind: "log", Profile: "gstable@740526d03", ProfileSHA256: strings.Repeat("f", 64), SHA256: declaration.SHA256}} {
		if e = s.PutLogInput(ctx, r.ID, in); e != nil {
			t.Fatal(e)
		}
	}
	events := []logs.Event{{Input: "native", Node: a, Line: 1, Run: "writer", Wall: wall, Mono: &mono, Record: event.Record{Src: "event", Kind: event.MsgOutcome, Fields: map[string]any{"code": "19", "step": "2", "engine_run": "1", "dedup_key": key, "outcome": "ACCEPT"}}}, {Input: "legacy", Node: legacy, Line: 1, Run: "1", Wall: wall, Record: event.Record{Src: "log", Kind: event.MsgOutcome, Fields: map[string]any{"address": legacy, "msg.source": a, "msg.code": "19", "msg.sequence": "1", "msg.round": "0"}}}}
	for i, number := range []string{"1", "2"} {
		for _, input := range []string{"native", "legacy"} {
			src, node, run := "event", a, "writer"
			if input == "legacy" {
				src, node, run = "log", legacy, "1"
			}
			events = append(events, logs.Event{Input: input, Node: node, Line: int64(i + 2), Run: run, Wall: wall, Record: event.Record{Src: src, Kind: event.NewHead, Fields: map[string]any{"number": number, "hash": hash}}})
		}
	}
	if e = s.PutLogEvents(ctx, r.ID, events, int64(len(events))); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, r.ID, int64(len(events)), ""); e != nil {
		t.Fatal(e)
	}
	index, e := s.RebuildMessagePairs(ctx, m.ID, r.ID)
	if e != nil || len(index.LegacyAssociations) != 1 || index.LegacyAssociations[0].HeadAnchors != 2 {
		t.Fatal(index, e)
	}
	_, pairs, e := s.MessagePairData(ctx, m.ID, PairFilter{Sender: a, Receiver: legacy, Strength: "key"})
	if e != nil || len(pairs) != 1 || pairs[0].Metric != "propagation_processing" || pairs[0].Receive == nil || pairs[0].Receive.Kind != "log" || pairs[0].Receive.Association != "declared_head_anchors" {
		t.Fatal(pairs, e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE log_inputs SET sha256=$3 WHERE dataset_id=$1 AND input_id=$2`, r.ID, "legacy", strings.Repeat("9", 64)); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.MessagePairData(ctx, m.ID, PairFilter{}); e == nil {
		t.Fatal("changed pinned input did not invalidate old projection")
	}
	if _, e = s.RebuildMessagePairs(ctx, m.ID, r.ID); e == nil {
		t.Fatal("changed declaration snapshot accepted")
	}
}
