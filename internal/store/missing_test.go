package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
)

func missingFixture(t *testing.T, s *Store) (Dataset, Dataset, []headers.Fact) {
	t.Helper()
	ctx := context.Background()
	key := NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}
	hd, release, e := s.BeginRange(ctx, key, "headers", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	members := []string{}
	for i := 1; i <= 4; i++ {
		members = append(members, fmt.Sprintf("0x%040x", i))
	}
	facts := []headers.Fact{}
	for i := 1; i <= 3; i++ {
		f := headers.Fact{Index: fmt.Sprint(i), Number: fmt.Sprint(i), Hash: "0x" + strings.Repeat(fmt.Sprint(i), 64), ParentHash: "0x" + strings.Repeat(fmt.Sprint(i-1), 64), Validators: members, Policy: "0", EpochInfo: json.RawMessage(`null`), PrevPrepared: []int64{0, 1, 2}, PrevCommitted: []int64{0, 1, 2}}
		facts = append(facts, f)
	}
	copies := []headers.Copy{}
	for _, f := range facts {
		copies = append(copies, headers.Copy{Index: f.Index, Hash: f.Hash, Node: "header-observer", Prepared: []int64{0, 1, 2}, Committed: []int64{0, 1, 2}})
	}
	if e = s.PutHeaders(ctx, hd.ID, hd.NetworkID, facts, copies, 3); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, hd.ID, 3, ""); e != nil {
		t.Fatal(e)
	}
	d, release, e := s.BeginRun(ctx, key, "events", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	n := members[3]
	if e = s.PutLogInput(ctx, d.ID, logs.InputSummary{ID: "events", Node: n, Kind: "events", Profile: logs.EventProfile, SHA256: strings.Repeat("a", 64), ProfileSHA256: strings.Repeat("b", 64)}); e != nil {
		t.Fatal(e)
	}
	rows := []logs.Event{}
	for i, k := range []event.Kind{event.NodeStart, event.RoundEnter, event.RoundEnter, event.NodeStop} {
		var v *event.View
		if k == event.RoundEnter {
			v = &event.View{Seq: fmt.Sprint(i), Round: "0"}
		}
		rows = append(rows, logs.Event{Input: "events", Node: n, Run: "r", Line: int64(i + 1), Wall: "2020-01-01T00:00:00Z", Profile: logs.EventProfile, Record: event.Record{Src: "event", Kind: k, View: v, Fields: map[string]any{"seq": fmt.Sprint(i), "validator": true}}})
	}
	if e = s.PutLogEvents(ctx, d.ID, rows, 4); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, d.ID, 4, ""); e != nil {
		t.Fatal(e)
	}
	return d, hd, facts
}
func TestMissingAtomicHeaderScopeAndSourceStaleness(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	d, hd, facts := missingFixture(t, s)
	f := MissingFilter{From: 1, To: 2}
	if _, _, _, e := s.MissingData(ctx, d.ID, f, 0, 1); !errors.Is(e, ErrMissingIndex) {
		t.Fatal("GET built a projection", e)
	}
	first, e := s.RebuildMissing(ctx, d.ID, 0, 1, 2)
	if e != nil {
		t.Fatal(e)
	}
	if first.Cells != 16 || first.Counts["NOT_SENT"] != 4 || first.Counts["SEALED"] != 12 {
		t.Fatal(first)
	}
	again, e := s.RebuildMissing(ctx, d.ID, 0, 1, 2)
	if e != nil || again.Snapshot != first.Snapshot {
		t.Fatal("rebuild changed identical snapshot", again, e)
	}
	index, rows, total, e := s.MissingData(ctx, d.ID, MissingFilter{From: 1, To: 2, Class: "NOT_SENT"}, 0, 1)
	if e != nil || total != 4 || len(rows) != 2 || index.Snapshot != first.Snapshot || rows[0].Evidence[0].Source.DatasetID != d.ID {
		t.Fatal(index, rows, total, e)
	}
	if _, _, _, e = s.MissingData(ctx, d.ID, MissingFilter{From: 0, To: 2}, 0, 1); !errors.Is(e, ErrMissingScope) {
		t.Fatal("query exceeded indexed scope", e)
	}
	if _, e = s.RebuildMissing(ctx, d.ID, 0, 1, 4); e == nil {
		t.Fatal("missing header accepted")
	}
	if _, _, _, e = s.MissingData(ctx, d.ID, f, 0, 100); e != nil {
		t.Fatal("failed rebuild destroyed old index", e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET progress=5 WHERE id=$1`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RebuildMissing(ctx, d.ID, 0, 1, 2); e == nil {
		t.Fatal("incomplete stored records accepted")
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET progress=4 WHERE id=$1`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = s.MissingData(ctx, d.ID, f, 0, 100); e != nil {
		t.Fatal("failed progress rebuild destroyed projection", e)
	}
	// A new copy changes header participation while the event input is unchanged.
	if e = s.PutHeaders(ctx, hd.ID, hd.NetworkID, []headers.Fact{facts[0]}, []headers.Copy{{Index: "1", Hash: facts[0].Hash, Node: "second", Prepared: []int64{3}, Committed: []int64{3}}}, 3); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = s.MissingData(ctx, d.ID, f, 0, 100); !errors.Is(e, ErrMissingIndex) {
		t.Fatal("new copy did not invalidate missing", e)
	}
	changed, e := s.RebuildMissing(ctx, d.ID, 0, 1, 2)
	if e != nil || changed.Snapshot == first.Snapshot || changed.Counts["NOT_SENT"] != 2 {
		t.Fatal(changed, e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE log_inputs SET stats='{"sequence_gaps":1}' WHERE dataset_id=$1`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = s.MissingData(ctx, d.ID, f, 0, 100); !errors.Is(e, ErrMissingIndex) {
		t.Fatal("input diagnostics changed without invalidating", e)
	}
	if _, e = s.RebuildMissing(ctx, d.ID, 0, 1, 2); e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET metadata='{"changed":true}' WHERE id=$1`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = s.MissingData(ctx, d.ID, f, 0, 100); !errors.Is(e, ErrMissingIndex) {
		t.Fatal("metadata-only source change accepted", e)
	}
}

func TestMissingVerifiedCompanionChangesAndDeletion(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	d, _, _ := missingFixture(t, s)
	key := NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}
	m, release, e := s.BeginMessages(ctx, key, "votes", json.RawMessage(`{"clock":{"model":"shared-host"}}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	node := "0x0000000000000000000000000000000000000004"
	dedup := "0x" + strings.Repeat("c", 64)
	mono := "0"
	wall := "2020-01-01T00:00:00Z"
	if e = s.PutMessageInput(ctx, m.ID, source.Summary{ID: "journal", Node: node, Kind: "journal"}); e != nil {
		t.Fatal(e)
	}
	records := []source.Record{{Input: "journal", File: "synthetic.wal", Ordinal: 1, Seq: "1", Node: node, Run: "r", Type: "outcome", Step: "5", Key: dedup, Phase: "PREPARE", Outcome: "ACCEPT"}, {Input: "journal", File: "synthetic.wal", Ordinal: 2, Seq: "2", Node: node, Run: "r", Type: "step", Step: "5", Wall: wall, Mono: &mono}}
	if e = s.PutMessageRecords(ctx, m.ID, records, 2); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, m.ID, 2, ""); e != nil {
		t.Fatal(e)
	}
	row := logs.Event{Input: "events", Node: node, Run: "r", Line: 5, Wall: wall, Mono: &mono, Profile: logs.EventProfile, Record: event.Record{Src: "event", Kind: event.MsgOutcome, View: &event.View{Seq: "1", Round: "0"}, Fields: map[string]any{"seq": "4", "step": "5", "dedup_key": dedup, "code": "19", "source": node, "outcome": "ACCEPT"}}}
	if e = s.PutLogEvents(ctx, d.ID, []logs.Event{row}, 5); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, d.ID, 5, ""); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RebuildMessagePairs(ctx, m.ID, d.ID); e != nil {
		t.Fatal(e)
	}
	first, e := s.RebuildMissing(ctx, d.ID, m.ID, 1, 2)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RebuildMissing(ctx, d.ID, m.ID+100, 1, 2); e == nil {
		t.Fatal("absent companion accepted")
	}
	if _, e = s.MissingIndex(ctx, d.ID); e != nil {
		t.Fatal("failed rebuild lost index", e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET metadata=jsonb_set(metadata,'{label}','"changed"') WHERE id=$1`, m.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.MissingIndex(ctx, d.ID); !errors.Is(e, ErrMissingIndex) {
		t.Fatal("changed journal accepted", e)
	}
	if _, e = s.RebuildMessagePairs(ctx, m.ID, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.MissingIndex(ctx, d.ID); !errors.Is(e, ErrMissingIndex) {
		t.Fatal("changed companion snapshot accepted", e)
	}
	next, e := s.RebuildMissing(ctx, d.ID, m.ID, 1, 2)
	if e != nil || next.Snapshot == first.Snapshot {
		t.Fatal(next, e)
	}
	if _, e = s.pool.Exec(ctx, `DELETE FROM datasets WHERE id=$1`, m.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.MissingIndex(ctx, d.ID); !errors.Is(e, ErrMissingIndex) {
		t.Fatal("deleted companion accepted", e)
	}
}
