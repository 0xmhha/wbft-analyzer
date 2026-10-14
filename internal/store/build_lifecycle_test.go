package store

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

func storedBuildRows() []logs.Event {
	rows := []logs.Event{}
	for i, kind := range []event.Kind{event.BuildHandover, event.BuildStarted, event.BuildFinished} {
		mono := strconv.Itoa(i * 20)
		fields := map[string]any{"build_id": "build-1", "number": "18446744073709551616", "wait_ns": "10"}
		if kind == event.BuildFinished {
			fields["status"] = "submitted"
			fields["hash"] = "0x" + strings.Repeat("a", 64)
		}
		rows = append(rows, logs.Event{Node: "0x" + strings.Repeat("1", 40), Input: "input", Run: "run", Wall: "2026-01-01T00:00:00Z", Profile: logs.EventProfile, Level: "event", Line: int64(i + 1), Mono: &mono, Record: event.Record{Kind: kind, Src: "event", View: &event.View{Seq: "18446744073709551616", Round: "0"}, Fields: fields}})
	}
	return rows
}
func TestBuildSourcePreservesExactInputRunAndDuplicateCandidates(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginRun(ctx, NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}, "build-evidence", json.RawMessage(`{"clock":"shared-host"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, input := range []string{"input", "other"} {
		err = s.PutLogInput(ctx, d.ID, logs.InputSummary{ID: input, Node: "0x" + strings.Repeat("1", 40), Kind: "events", Profile: logs.EventProfile, SHA256: strings.Repeat("a", 64), ProfileSHA256: strings.Repeat("b", 64), Bytes: 100})
		if err != nil {
			t.Fatal(err)
		}
		if err = s.FinishLogInput(ctx, d.ID, input, logs.Stats{Events: 3}); err != nil {
			t.Fatal(err)
		}
	}
	rows := storedBuildRows()
	foreign := storedBuildRows()
	for i := range foreign {
		foreign[i].Input = "other"
	}
	if err = s.PutLogEvents(ctx, d.ID, append(rows, foreign...), 6); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, d.ID, 6, ""); err != nil {
		t.Fatal(err)
	}
	got, err := s.BuildSource(ctx, d.ID, "input", 2)
	if err != nil || got.State != "complete" || len(got.Events) != 3 || got.AssemblyNS == nil || *got.AssemblyNS != "20" || got.Origin.Line != 2 {
		t.Fatal(got, err)
	}
	for _, x := range got.Events {
		if x.Input != "input" || x.Height != "18446744073709551616" {
			t.Fatal("foreign input or rounded height", x)
		}
	}
	if err = s.FinishLogInput(ctx, d.ID, "input", logs.Stats{Events: 3, SequenceGaps: 1}); err != nil {
		t.Fatal(err)
	}
	got, err = s.BuildSource(ctx, d.ID, "input", 2)
	if err != nil || got.State != "incomplete" || got.AssemblyNS != nil {
		t.Fatal("gap manufactured a unique measurement", got, err)
	}
	if err = s.FinishLogInput(ctx, d.ID, "input", logs.Stats{Events: 4}); err != nil {
		t.Fatal(err)
	}
	duplicate := rows[2]
	duplicate.Line = 4
	if err = s.PutLogEvents(ctx, d.ID, []logs.Event{duplicate}, 7); err != nil {
		t.Fatal(err)
	}
	got, err = s.BuildSource(ctx, d.ID, "input", 2)
	if err != nil || got.State != "ambiguous" || len(got.Events) != 4 || got.AssemblyNS != nil {
		t.Fatal("duplicate completion selected", got, err)
	}
}
func TestBuildProjectionDoesNotInventClocksOrConsensusAcceptance(t *testing.T) {
	source := storedBuildRows()
	rows := []LogEvent{}
	for _, x := range source {
		fields, _ := json.Marshal(x.Record.Fields)
		rows = append(rows, LogEvent{Source: "event", Profile: logs.EventProfile, Node: x.Node, Input: x.Input, Run: x.Run, Line: x.Line, Kind: x.Record.Kind, Height: x.Record.View.Seq, Round: x.Record.View.Round, Mono: x.Mono, Fields: fields})
	}
	for _, change := range []string{"missing_clock", "wrong_view", "wrong_input", "failed"} {
		copyRows := append([]LogEvent(nil), rows...)
		switch change {
		case "missing_clock":
			copyRows[1].Mono = nil
		case "wrong_view":
			copyRows[2].Round = "1"
		case "wrong_input":
			copyRows[2].Input = "other"
		case "failed":
			copyRows[2].Fields = json.RawMessage(`{"build_id":"build-1","number":"18446744073709551616","status":"failed"}`)
		}
		out := BuildLifecycle{State: "incomplete", Origin: copyRows[0], BuildID: "build-1", Events: copyRows}
		projectBuildLifecycle(&out, true)
		if change == "failed" {
			if out.State != "complete" || out.Status != "failed" || out.AssemblyNS != nil {
				t.Fatal(out)
			}
		} else if out.State != "incomplete" || out.AssemblyNS != nil {
			t.Fatal(change, out)
		}
	}
}
