package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
	"strings"
	"testing"
)

func TestMixedReindexUsesVerifiedDependencyAndRollsBackConflict(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	network := NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}
	m, release, e := s.BeginMessages(ctx, network, "mixed-journal", json.RawMessage(`{"clock":{"model":"shared-host"}}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	r, release, e := s.BeginRun(ctx, network, "mixed-events", json.RawMessage(`{"clock":"shared-host"}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	key := "0x" + strings.Repeat("a", 64)
	a := "0x0000000000000000000000000000000000000001"
	b := "0x0000000000000000000000000000000000000002"
	lo, hi := "0", "20000000"
	wall := "2020-01-01T00:00:00Z"
	later := "2020-01-01T00:00:00.020Z"
	for _, n := range []string{a, b} {
		if e = s.PutMessageInput(ctx, m.ID, source.Summary{ID: n, Node: n, Kind: "journal"}); e != nil {
			t.Fatal(e)
		}
		if e = s.PutLogInput(ctx, r.ID, logs.InputSummary{ID: n, Node: n, Kind: "events", Profile: "wbft@events-v1", SHA256: strings.Repeat("b", 64), ProfileSHA256: strings.Repeat("c", 64)}); e != nil {
			t.Fatal(e)
		}
	}
	records := []source.Record{
		{Input: a, File: "00000000000000000000.wal", Ordinal: 1, Seq: "1", Node: a, Run: "r", Type: "frame", Dir: "out", Peer: b, Key: key, Phase: "PREPARE", Decode: "decoded", Height: "1", Round: "0", Write: "ok", Wall: wall, Mono: &lo},
		{Input: a, File: "00000000000000000000.wal", Ordinal: 2, Seq: "2", Node: a, Run: "r", Type: "outcome", Key: key, Phase: "PREPARE", Outcome: "ACCEPT", Step: "2"},
		{Input: a, File: "00000000000000000000.wal", Ordinal: 3, Seq: "3", Node: a, Run: "r", Type: "step", Step: "2", Wall: wall, Mono: &lo},
		{Input: b, File: "00000000000000000000.wal", Ordinal: 1, Seq: "1", Node: b, Run: "r", Type: "frame", Dir: "in", Peer: a, Key: key, Phase: "PREPARE", Decode: "decoded", Height: "1", Round: "0", Wall: later, Mono: &hi},
		{Input: b, File: "00000000000000000000.wal", Ordinal: 2, Seq: "2", Node: b, Run: "r", Type: "outcome", Key: key, Phase: "PREPARE", Outcome: "ACCEPT", Step: "3"},
		{Input: b, File: "00000000000000000000.wal", Ordinal: 3, Seq: "3", Node: b, Run: "r", Type: "step", Step: "3", Wall: later, Mono: &hi},
	}
	if e = s.PutMessageRecords(ctx, m.ID, records, 6); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, m.ID, 6, ""); e != nil {
		t.Fatal(e)
	}
	events := []logs.Event{
		{Input: a, Node: a, Run: "r", Line: 1, Wall: wall, Mono: &lo, Profile: "wbft@events-v1", Record: event.Record{Kind: event.Send, Src: "event", Fields: map[string]any{"code": "19", "cause": "broadcast", "dedup_key": key}}},
		{Input: a, Node: a, Run: "r", Line: 2, Wall: wall, Mono: &lo, Profile: "wbft@events-v1", Record: event.Record{Kind: event.MsgOutcome, Src: "event", View: &event.View{Seq: "1", Round: "0"}, Fields: map[string]any{"code": "19", "step": "2", "source": a, "dedup_key": key, "outcome": "ACCEPT"}}},
		{Input: b, Node: b, Run: "r", Line: 1, Wall: later, Mono: &hi, Profile: "wbft@events-v1", Record: event.Record{Kind: event.MsgOutcome, Src: "event", View: &event.View{Seq: "1", Round: "0"}, Fields: map[string]any{"code": "19", "step": "3", "source": a, "dedup_key": key, "outcome": "ACCEPT"}}},
	}
	if e = s.PutLogEvents(ctx, r.ID, events, 3); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, r.ID, 3, ""); e != nil {
		t.Fatal(e)
	}
	index, e := s.RebuildMessagePairs(ctx, m.ID, r.ID)
	if e != nil || index.Association == nil || index.Association.Status != "matched" || index.Records != 9 {
		t.Fatal(index, e)
	}
	if len(index.Coverage) != 4 || index.Coverage[0].DatasetID != m.ID || index.Coverage[2].DatasetID != r.ID {
		t.Fatal("companion coverage is missing or ambiguous", index.Coverage)
	}
	_, pairs, e := s.MessagePairData(ctx, m.ID, PairFilter{Sender: a, Receiver: b})
	if e != nil || len(pairs) != 1 || pairs[0].Strength != "link" || pairs[0].Send.DatasetID != m.ID {
		t.Fatal(pairs, e)
	}
	// A source append invalidates the dependent projection even if the parent
	// journal's own metadata/progress/status stay unchanged.
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET progress=4 WHERE id=$1`, r.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = s.MessageIssueData(ctx, m.ID, IssueFilter{}, 0, 10); !errors.Is(e, ErrPairIndex) {
		t.Fatal("stale companion issues accepted", e)
	}
	if _, _, e = s.MessagePairData(ctx, m.ID, PairFilter{}); !errors.Is(e, ErrPairIndex) {
		t.Fatal("dependent append not invalidated", e)
	}
	if _, e = s.RebuildMessagePairs(ctx, m.ID, r.ID); e == nil {
		t.Fatal("source count mismatch accepted")
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET progress=3 WHERE id=$1`, r.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.MessagePairData(ctx, m.ID, PairFilter{}); e != nil {
		t.Fatal("rollback lost prior dependency", e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET metadata=jsonb_set(metadata,'{label}','"updated"') WHERE id=$1`, r.ID); e != nil {
		t.Fatal(e)
	}
	changed, e := s.RebuildMessagePairs(ctx, m.ID, r.ID)
	if e != nil || changed.Snapshot == index.Snapshot {
		t.Fatal("companion metadata omitted from snapshot", e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET metadata=jsonb_set(metadata,'{label}','"updated"') WHERE id=$1`, m.ID); e != nil {
		t.Fatal(e)
	}
	parentChanged, e := s.RebuildMessagePairs(ctx, m.ID, r.ID)
	if e != nil || parentChanged.Snapshot == changed.Snapshot {
		t.Fatal("parent metadata omitted from snapshot", e)
	}
	if _, e = s.pool.Exec(ctx, `DELETE FROM datasets WHERE id=$1`, r.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = s.MessageIssueData(ctx, m.ID, IssueFilter{}, 0, 10); !errors.Is(e, ErrPairIndex) {
		t.Fatal("stale companion issues accepted", e)
	}
	if _, _, e = s.MessagePairData(ctx, m.ID, PairFilter{}); !errors.Is(e, ErrPairIndex) {
		t.Fatal("deleted source not invalidated", e)
	}
}
