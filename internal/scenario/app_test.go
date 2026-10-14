package scenario

import (
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"strconv"
	"testing"
	"time"
)

func TestAppTimingPreservesWaitAndFailureEvidence(t *testing.T) {
	rec := func(kind event.Kind, line int64, mono time.Duration, fields map[string]any) logs.Event {
		m := strconv.FormatInt(int64(mono), 10)
		return logs.Event{Node: "a", Input: "i", Run: "r", Profile: logs.EventProfile, Line: line, Mono: &m, Record: event.Record{Kind: kind, View: &event.View{Seq: "1", Round: "0"}, Fields: fields}}
	}
	build := rec(event.BuildRequest, 1, time.Second, map[string]any{"wait_ms": "100"})
	submit := rec(event.ProposalSubmitted, 2, time.Second+120*time.Millisecond, map[string]any{"number": "1"})
	commit := rec(event.CommitResult, 3, 2*time.Second, map[string]any{"duration_ms": "7", "ok": true})
	got, err := FitAppTiming([]logs.Event{build, submit, commit})
	if err != nil || len(got.Build) != 1 || got.Build[0].Nanoseconds != 20000000 || len(got.Import) != 1 || got.Import[0].Nanoseconds != 7000000 || got.Unproved != 0 {
		t.Fatalf("app %+v %v", got, err)
	}
	got, err = FitAppTiming([]logs.Event{build, build, submit})
	if err != nil || len(got.Build) != 0 || got.Unproved == 0 {
		t.Fatal("ambiguous request accepted")
	}
	commit.Record.Fields["ok"] = false
	got, err = FitAppTiming([]logs.Event{commit})
	if err != nil || len(got.Import) != 0 {
		t.Fatal("failed import modeled as success")
	}
	submit.Mono = nil
	got, err = FitAppTiming([]logs.Event{build, submit})
	if err != nil || len(got.Build) != 0 {
		t.Fatal("missing mono inferred")
	}
}
