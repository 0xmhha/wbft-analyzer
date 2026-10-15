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
	metadata, e := json.Marshal(map[string]string{"events_normalizer": logs.EventNormalizer})
	if e != nil {
		t.Fatal(e)
	}
	d, release, e := s.BeginRun(ctx, key, "events", metadata)
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

func TestMissingRequiresHealthPreservingNormalizerForAbsence(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, _, _ := missingFixture(t, s)
	index, err := s.RebuildMissing(ctx, d.ID, 0, 1, 2)
	if err != nil || index.Counts["NOT_SENT"] != 4 {
		t.Fatal(index, err)
	}
	// A pre-fix index is never served merely because its source is unchanged.
	if _, err = s.pool.Exec(ctx, `UPDATE missing_indexes SET version='wbft-missing/1' WHERE dataset_id=$1`, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = s.MissingData(ctx, d.ID, MissingFilter{From: 1, To: 2}, 0, 100); !errors.Is(err, ErrMissingIndex) {
		t.Fatal("old index remained ready", err)
	}
	for _, version := range []string{"", "wbft-event-normalization/4", "unrecognized"} {
		metadata, err := json.Marshal(map[string]string{"events_normalizer": version})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.pool.Exec(ctx, `UPDATE datasets SET metadata=$2 WHERE id=$1`, d.ID, metadata); err != nil {
			t.Fatal(err)
		}
		index, err = s.RebuildMissing(ctx, d.ID, 0, 1, 2)
		if err != nil || index.Counts["NOT_SENT"] != 0 || index.Counts["UNKNOWN"] != 4 || index.Counts["SEALED"] != 12 {
			t.Fatal("unproven normalization granted absence or lost positive seals", version, index, err)
		}
	}
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

func TestMissingJournalCheckpointContextPointersAndInvalidation(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, _, facts := missingFixture(t, s)
	node := facts[0].Validators[3]
	wall := "2020-01-01T00:00:00Z"
	if _, err := s.pool.Exec(ctx, `DELETE FROM log_events WHERE dataset_id=$1`, d.ID); err != nil {
		t.Fatal(err)
	}
	var rows []logs.Event
	for i, kind := range []event.Kind{event.NodeStart, event.RoundEnter, event.MsgOutcome, event.NewHead, event.NodeStop} {
		mono := []string{"1", "2", "20", "30", "40"}[i]
		fields := map[string]any{"seq": fmt.Sprint(i), "validator": true}
		var view *event.View
		switch kind {
		case event.RoundEnter:
			view = &event.View{Seq: "1", Round: "0"}
		case event.MsgOutcome:
			view = &event.View{Seq: "1", Round: "0"}
			fields["step"] = "2"
			fields["dedup_key"] = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			fields["code"] = "19"
			fields["source"] = facts[0].Validators[0]
			fields["outcome"] = "ACCEPT"
		case event.NewHead:
			view = &event.View{Seq: "3", Round: "0"}
			fields["hash"] = facts[2].Hash
		}
		rows = append(rows, logs.Event{Input: "events", Node: node, Run: "r", Line: int64(i + 1), Wall: wall, Mono: &mono, Profile: logs.EventProfile, Record: event.Record{Src: "event", Kind: kind, View: view, Fields: fields}})
	}
	if err := s.PutLogEvents(ctx, d.ID, rows, 5); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRange(ctx, d.ID, 5, ""); err != nil {
		t.Fatal(err)
	}
	m, release, err := s.BeginMessages(ctx, NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}, "checkpoint", json.RawMessage(`{"clock":{"model":"shared-host"}}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = s.PutMessageInput(ctx, m.ID, source.Summary{ID: "journal", Node: node, Kind: "journal"}); err != nil {
		t.Fatal(err)
	}
	a, b := "10", "20"
	records := []source.Record{
		{Input: "journal", File: "synthetic.wal", Ordinal: 1, Seq: "1", Node: node, Run: "r", Type: "segment"},
		{Input: "journal", File: "synthetic.wal", Ordinal: 2, Seq: "2", Node: node, Run: "r", Type: "step", Step: "1", ClockSource: "recorded", Wall: wall, Mono: &a, HeadNumber: "1", HeadHash: facts[0].Hash},
		{Input: "journal", File: "synthetic.wal", Ordinal: 3, Seq: "3", Node: node, Run: "r", Type: "outcome", Step: "2", Key: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: "PREPARE", Outcome: "ACCEPT"},
		{Input: "journal", File: "synthetic.wal", Ordinal: 4, Seq: "4", Node: node, Run: "r", Type: "step", Step: "2", ClockSource: "recorded", Wall: wall, Mono: &b},
	}
	if err = s.PutMessageRecords(ctx, m.ID, records, 4); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, m.ID, 4, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RebuildMessagePairs(ctx, m.ID, d.ID); err != nil {
		t.Fatal(err)
	}
	first, err := s.RebuildMissing(ctx, d.ID, m.ID, 2, 2)
	if err != nil || first.Counts["NOT_SENT"] != 2 || first.CheckpointSnapshot == "" {
		t.Fatal("outside-range journal head lost", first, err)
	}
	_, cells, _, err := s.MissingData(ctx, d.ID, MissingFilter{From: 2, To: 2, Class: "NOT_SENT"}, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	journal := 0
	for _, c := range cells {
		for _, p := range c.Evidence {
			if p.Source.Kind == "message" {
				journal++
				if p.Source.DatasetID != m.ID || p.Source.Ordinal != 2 || p.Source.File != "synthetic.wal" {
					t.Fatal("wrong journal pointer", p)
				}
			} else if p.Source.DatasetID != d.ID {
				t.Fatal("wrong event pointer", p)
			}
		}
	}
	if journal != 2 {
		t.Fatal("journal proof absent", journal)
	}
	if _, err = s.pool.Exec(ctx, `UPDATE message_records SET record=jsonb_set(record,'{head_hash}','"changed"') WHERE dataset_id=$1 AND ordinal=2`, m.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.MissingIndex(ctx, d.ID); !errors.Is(err, ErrMissingIndex) {
		t.Fatal("checkpoint changed without staling index", err)
	}
	records[1].HeadHash = "changed"
	if err = s.PutMessageRecords(ctx, m.ID, records, 4); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RebuildMessagePairs(ctx, m.ID, d.ID); err != nil {
		t.Fatal(err)
	}
	next, err := s.RebuildMissing(ctx, d.ID, m.ID, 2, 2)
	if err != nil || next.Counts["NOT_SENT"] != 0 || next.Counts["UNKNOWN"] != 2 {
		t.Fatal("foreign checkpoint became absence", next, err)
	}
}
