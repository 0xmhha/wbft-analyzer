package replay

import (
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"reflect"
	"testing"
	"time"
)

func record(kind event.Kind, line int64, fields map[string]any) logs.Event {
	return logs.Event{Record: event.Record{Kind: kind, View: &event.View{Seq: "18446744073709551617", Round: "0"}, Fields: fields, Src: "event"}, Node: "n", Input: "i", Run: "r", Wall: "2026-10-13T00:00:00Z", Line: line}
}
func TestRecordedStateAndTimerGeneration(t *testing.T) {
	s := New("n")
	Apply(&s, record(event.RoundEnter, 1, map[string]any{"cause": "timeout"}))
	if s.ConsensusState != "" || s.Cause != "timeout" {
		t.Fatal(s)
	}
	Apply(&s, record(event.TimerArm, 2, map[string]any{"timer": "round", "gen": "4", "engine_run": "1", "deadline_mono_ns": "100"}))
	Apply(&s, record(event.TimerFire, 3, map[string]any{"timer": "round", "gen": "3", "engine_run": "1", "stale": true}))
	if s.Timers["round"].Status != "armed" {
		t.Fatal(s)
	}
	Apply(&s, record(event.TimerCancel, 4, map[string]any{"timer": "round", "gen": "3", "engine_run": "1"}))
	if s.Timers["round"].Status != "armed" || s.UnmatchedTimerEvents != 1 {
		t.Fatal(s)
	}
	Apply(&s, record(event.TimerCancel, 5, map[string]any{"timer": "round", "gen": "4", "engine_run": "1"}))
	if s.Timers["round"].Status != "cancelled" {
		t.Fatal(s)
	}
	future := record(event.MsgOutcome, 6, map[string]any{"outcome": "ACCEPT"})
	future.Record.View = &event.View{Seq: "9", Round: "2"}
	Apply(&s, future)
	if s.View.Seq != "18446744073709551617" {
		t.Fatal("message view became node view", s)
	}
	Apply(&s, record(event.StateChange, 7, map[string]any{"to": "Prepared"}))
	if s.ConsensusState != "Prepared" {
		t.Fatal(s)
	}
	Apply(&s, record(event.EngineStop, 8, nil))
	if s.View != nil || s.ConsensusState != "" || len(s.Timers) != 0 {
		t.Fatal(s)
	}
}
func TestSnapshotsOwnStateAndMatchPrefixFold(t *testing.T) {
	es := []logs.Event{record(event.RoundEnter, 1, map[string]any{})}
	for i := int64(2); i < 4000; i++ {
		es = append(es, record(event.Backlog, i, map[string]any{"op": "push"}))
	}
	frames := Build(es)
	if len(frames) != 4 {
		t.Fatal("unexpected snapshot count", len(frames))
	}
	s := New("n")
	frame := 0
	for _, e := range Ordered(es) {
		Apply(&s, e)
		if frame < len(frames) && frames[frame].Line == e.Line {
			if !reflect.DeepEqual(s, frames[frame].State) {
				t.Fatalf("snapshot mismatch at %d", e.Line)
			}
			frame++
		}
	}
	if frames[1].State.Backlog == nil || *frames[1].State.Backlog != 1023 || !frames[1].State.BacklogPartial {
		t.Fatal("snapshots aliased or fabricated prefix", frames[1])
	}
}

func TestSeekMatchesWholePrefixAtArbitraryTimes(t *testing.T) {
	es := []logs.Event{}
	origin := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	for i := int64(1); i <= 6000; i++ {
		e := record(event.Backlog, i, map[string]any{"op": "push"})
		e.Wall = origin.Add(time.Duration(i) * time.Microsecond).Format(time.RFC3339Nano)
		es = append(es, e)
	}
	frames := Build(es)
	for i := 0; i < 100; i++ {
		target := origin.Add(time.Duration((i*127)%6001) * time.Microsecond)
		want := New("n")
		for _, e := range es {
			at, _ := time.Parse(time.RFC3339Nano, e.Wall)
			if !at.After(target) {
				Apply(&want, e)
			}
		}
		got, _ := Seek(es, frames, "n", target)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("seek differs at %v", target)
		}
	}
}
