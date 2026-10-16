package messages

import (
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
)

func TestAssociationUsesMeasuredFrameCompletions(t *testing.T) {
	for _, kind := range []string{"scheduler_step", "own_input"} {
		for _, tc := range []struct {
			name    string
			change  func([]source.Record, []logs.Event)
			matched bool
		}{
			{"exact", func(_ []source.Record, _ []logs.Event) {}, true},
			{"unstepped observation", func(rs []source.Record, _ []logs.Event) { rs[0].Step = "0" }, true},
			{"outcome engine mismatch", func(rs []source.Record, _ []logs.Event) { rs[1].EngineRun = "2" }, false},
			{"different outcome", func(_ []source.Record, es []logs.Event) { es[0].Record.Fields["dedup_key"] = "different" }, false},
			{"different engine", func(_ []source.Record, es []logs.Event) { es[0].Record.Fields["engine_run"] = "2" }, false},
			{"different clock", func(_ []source.Record, es []logs.Event) { v := "8"; es[0].Mono = &v }, false},
			{"missing clock", func(rs []source.Record, _ []logs.Event) { rs[2].Mono = nil }, false},
			{"missing wall", func(rs []source.Record, _ []logs.Event) { rs[2].Wall = "" }, false},
			{"inherited clock", func(rs []source.Record, _ []logs.Event) { rs[2].ClockSource = "inherited" }, false},
			{"missing position", func(rs []source.Record, _ []logs.Event) { rs[2].Journal = nil }, false},
			{"missing engine", func(rs []source.Record, _ []logs.Event) { rs[2].EngineRun = "" }, false},
			{"unrelated frame", func(rs []source.Record, _ []logs.Event) { rs[2].Type = "frame" }, false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				mono := "7"
				wall := "2020-01-01T00:00:00.000000007Z"
				rs := []source.Record{
					{Input: "j", Node: "a", Run: "r", Ordinal: 1, Type: "outcome", Key: "outside", Phase: "PREPARE", Outcome: "DROP_SILENT"},
					{Input: "j", Node: "a", Run: "r", Ordinal: 2, Type: "outcome", Step: "3", Key: "bytes", Phase: "PREPARE", Outcome: "ACCEPT"},
					{Input: "j", Node: "a", Run: "r", Ordinal: 3, Type: kind, Step: "3", EngineRun: "1", Wall: wall, Mono: &mono, ClockSource: "recorded", Journal: &source.JournalPosition{Segment: "0", Offset: "10"}},
				}
				if kind == "own_input" {
					rs[2].OwnInput = &source.OwnInputEvidence{EngineRun: "1", Step: "3"}
				}
				es := []logs.Event{{Input: "e", Node: "a", Run: "r", Line: 1, Wall: wall, Mono: &mono, Record: event.Record{Src: "event", Kind: event.MsgOutcome, Fields: map[string]any{"step": "3", "engine_run": "1", "dedup_key": "bytes", "phase": "PREPARE", "outcome": "ACCEPT"}}}}
				tc.change(rs, es)
				p := VerifyAssociation(rs, es)
				if (p.Status == "matched") != tc.matched {
					t.Fatalf("unexpected association: %+v", p)
				}
				if tc.matched && (p.MatchedAnchors != 1 || p.MissingAnchors != 0 || p.ConflictingAnchors != 0) {
					t.Fatal(p)
				}
				if tc.matched {
					for _, change := range []func(){func() { rs[2].OwnInput = nil }, func() { rs[2].OwnInput = &source.OwnInputEvidence{EngineRun: "2", Step: "3"} }} {
						if kind == "own_input" {
							change()
							if VerifyAssociation(rs, es).Status == "matched" {
								t.Fatal("unverified own completion proved association")
							}
						}
					}
				}
			})
		}
	}
}

func TestFrameAssociationKeepsCompletionIntervalsInEngineScope(t *testing.T) {
	for _, kind := range []string{"scheduler_step", "own_input"} {
		t.Run(kind, func(t *testing.T) {
			lo, hi, mid := "10", "30", "20"
			completion := func(step, wall string, mono *string) source.Record {
				r := source.Record{Input: "j", Node: "a", Run: "r", Type: kind, Step: step, EngineRun: "1", Wall: wall, Mono: mono, ClockSource: "recorded", Journal: &source.JournalPosition{Segment: "0", Offset: step}}
				if kind == "own_input" {
					r.OwnInput = &source.OwnInputEvidence{EngineRun: "1", Step: step}
				}
				return r
			}
			rs := []source.Record{
				completion("1", "2020-01-01T00:00:00.000000010Z", &lo),
				{Input: "j", Node: "a", Run: "r", Type: "outcome", Step: "2", Key: "bytes", Phase: "PREPARE", Outcome: "ACCEPT"},
				completion("2", "2020-01-01T00:00:00.000000030Z", &hi),
			}
			for i := range rs {
				rs[i].Ordinal = int64(i + 1)
			}
			es := []logs.Event{{Input: "e", Node: "a", Run: "r", Line: 1, Wall: "2020-01-01T00:00:00.000000020Z", Mono: &mid, Record: event.Record{Src: "event", Kind: event.MsgOutcome, Fields: map[string]any{"engine_run": "1", "step": "2", "dedup_key": "bytes", "phase": "PREPARE", "outcome": "ACCEPT"}}}}
			p := VerifyAssociation(rs, es)
			if p.Status != "matched" || p.Anchors[0].ClockBasis != "completed_step_interval" {
				t.Fatal(p)
			}
			if VerifyAssociation(rs[1:], es).Status == "matched" {
				t.Fatal("missing prior boundary proved association")
			}
			rs[0].EngineRun = "2"
			if kind == "own_input" {
				rs[0].OwnInput.EngineRun = "2"
			}
			if VerifyAssociation(rs, es).Status == "matched" {
				t.Fatal("different engine supplied a prior completion boundary")
			}
		})
	}
}

func TestAssociationRetainsExplicitRawOutcomeEngine(t *testing.T) {
	mono := "7"
	wall := "2020-01-01T00:00:00.000000007Z"
	rs := []source.Record{
		{Input: "j", Node: "a", Run: "r", Ordinal: 1, Type: "outcome", Step: "3", EngineRun: "1", Key: "bytes", Phase: "PREPARE", Outcome: "ACCEPT"},
		{Input: "j", Node: "a", Run: "r", Ordinal: 2, Type: "step", Step: "3", EngineRun: "1", Wall: wall, Mono: &mono},
	}
	es := []logs.Event{{Input: "e", Node: "a", Run: "r", Line: 1, Wall: wall, Mono: &mono, Record: event.Record{Src: "event", Kind: event.MsgOutcome, Fields: map[string]any{"engine_run": "1", "step": "3", "dedup_key": "bytes", "phase": "PREPARE", "outcome": "ACCEPT"}}}}
	if VerifyAssociation(rs, es).Status != "matched" {
		t.Fatal("equal recorded engine rejected")
	}
	rs[0].EngineRun = "2"
	if VerifyAssociation(rs, es).Status == "matched" {
		t.Fatal("completion overwrote an explicit outcome engine")
	}
}
