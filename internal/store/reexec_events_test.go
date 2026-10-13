package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
)

func TestReplayEventsRequireRecordedEngineAndSameSource(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	n := NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}
	m, release, e := s.BeginMessages(ctx, n, "journal", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	r, release, e := s.BeginRun(ctx, n, "events", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	sha := strings.Repeat("a", 64)
	node := "node"
	file := "00000000000000000000.wal"
	engine := "18446744073709551615"
	mono := "20"
	wall := "2020-01-01T00:00:00Z"
	key := "0x" + strings.Repeat("b", 64)
	if e = s.PutMessageInput(ctx, m.ID, source.Summary{ID: "journal", Kind: "journal", Node: node, SHA256: sha}); e != nil {
		t.Fatal(e)
	}
	records := []source.Record{{Input: "journal", File: file, Ordinal: 1, Seq: "1", Node: node, Run: "writer", Type: "outcome", EngineRun: engine, Step: "2", Key: key, Phase: "PREPARE", Outcome: "ACCEPT"}, {Input: "journal", File: file, Ordinal: 2, Seq: "2", Node: node, Run: "writer", Type: "step", EngineRun: engine, Step: "2", Mono: &mono, Wall: wall}}
	if e = s.PutMessageRecords(ctx, m.ID, records, 2); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, m.ID, 2, ""); e != nil {
		t.Fatal(e)
	}
	in := logs.InputSummary{ID: "event", Kind: "events", Node: node, Profile: "wbft@events-v1", ProfileSHA256: strings.Repeat("c", 64), SHA256: sha}
	if e = s.PutLogInput(ctx, r.ID, in); e != nil {
		t.Fatal(e)
	}
	events := []logs.Event{{Input: "event", Line: 1, Node: node, Run: "writer", Wall: wall, Mono: &mono, Record: event.Record{Src: "event", Kind: event.MsgOutcome, Fields: map[string]any{"code": "19", "step": "2", "engine_run": engine, "dedup_key": key, "outcome": "ACCEPT"}}}, {Input: "event", Line: 2, Node: node, Run: "writer", Wall: wall, Mono: &mono, Record: event.Record{Src: "event", Kind: event.StateChange, Fields: map[string]any{"step": "2", "engine_run": engine, "from": "AcceptRequest", "to": "Prepared"}}}, {Input: "event", Line: 3, Node: node, Run: "writer", Wall: wall, Mono: &mono, Record: event.Record{Src: "event", Kind: event.StateChange, Fields: map[string]any{"step": "2", "engine_run": "7", "from": "AcceptRequest", "to": "Prepared"}}}}
	if e = s.PutLogEvents(ctx, r.ID, events, 3); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, r.ID, 3, ""); e != nil {
		t.Fatal(e)
	}
	result := reexec.Result{SourceSHA: sha, Status: "running"}
	id, e := s.BeginReexec(ctx, m.ID, "journal", "1", "1", "private", result)
	if e != nil {
		t.Fatal(e)
	}
	step := reexec.Step{Ordinal: 2, File: file, Run: "writer", Engine: engine, Number: "2", Height: "1", Class: "match"}
	if e = s.PutReexecStep(ctx, id, step); e != nil {
		t.Fatal(e)
	}
	got, e := s.ReexecEvents(ctx, m.ID, id, 2, r.ID)
	if e != nil || got.Status != "matched" || len(got.Events) != 2 || got.Events[1].Line != 2 {
		t.Fatal(got, e)
	}
	if _, e = s.ReexecEvents(ctx, m.ID, id, 99, r.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	// A source hash drift refuses the association even with identical names.
	if _, e = s.pool.Exec(ctx, `UPDATE reexec_runs SET summary=jsonb_set(summary,'{source_sha256}','"different"') WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	got, e = s.ReexecEvents(ctx, m.ID, id, 2, r.ID)
	if e != nil || got.Reason != "source_identity_mismatch" || len(got.Events) != 0 {
		t.Fatal(got, e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE reexec_runs SET summary=jsonb_set(summary,'{source_sha256}',to_jsonb($2::text)) WHERE id=$1`, id, sha); e != nil {
		t.Fatal(e)
	}
	// Old events may establish a run association via unique inference, but a
	// replay step link still requires the explicitly recorded engine.
	if _, e = s.pool.Exec(ctx, `UPDATE log_events SET event=event #- '{fields,engine_run}' WHERE dataset_id=$1`, r.ID); e != nil {
		t.Fatal(e)
	}
	got, e = s.ReexecEvents(ctx, m.ID, id, 2, r.ID)
	if e != nil || got.Reason != "association_insufficient" || len(got.Events) != 0 {
		t.Fatal(got, e)
	}
	// Restore the source, then introduce a competing pointer in another input.
	if _, e = s.pool.Exec(ctx, `DELETE FROM log_events WHERE dataset_id=$1`, r.ID); e != nil {
		t.Fatal(e)
	}
	in.ID = "copy"
	if e = s.PutLogInput(ctx, r.ID, in); e != nil {
		t.Fatal(e)
	}
	duplicate := events[1]
	duplicate.Input = "copy"
	events = append(events, duplicate)
	if e = s.PutLogEvents(ctx, r.ID, events, 4); e != nil {
		t.Fatal(e)
	}
	got, e = s.ReexecEvents(ctx, m.ID, id, 2, r.ID)
	if e != nil || got.Reason != "ambiguous_event_input" || len(got.Events) != 0 {
		t.Fatal(got, e)
	}
	// An oversized step refuses all output instead of truncating pointers.
	extra := make([]logs.Event, 1000)
	for i := range extra {
		extra[i] = events[1]
		extra[i].Line = int64(i + 100)
	}
	if e = s.PutLogEvents(ctx, r.ID, extra, 1004); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReexecEvents(ctx, m.ID, id, 2, r.ID); !errors.Is(e, ErrPairSource) {
		t.Fatal("oversized event step accepted", e)
	}

	// Source progress and kind changes invalidate evidence on the next read.
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET status='failed' WHERE id=$1`, r.ID); e != nil {
		t.Fatal(e)
	}
	got, e = s.ReexecEvents(ctx, m.ID, id, 2, r.ID)
	if e != nil || got.Reason != "event_source_unavailable" {
		t.Fatal(got, e)
	}
}
