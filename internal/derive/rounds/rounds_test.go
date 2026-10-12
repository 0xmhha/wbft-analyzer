package rounds

import (
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

func row(kind event.Kind, node, h, r, wall string, line int64) logs.Event {
	return logs.Event{Record: event.Record{Kind: kind, View: &event.View{Seq: h, Round: r}, Fields: map[string]any{}}, Node: node, Input: "log-1", Run: "log-1:1", Profile: "gstable@740526d03", Line: line, Wall: wall}
}
func TestCorrelatedCausesAreBoundToHeightRunAndClock(t *testing.T) {
	a := row(event.TimerFire, "n1", "18446744073709551617", "1", "2026-10-13T00:00:01Z", 1)
	b := row(event.RoundEnter, "n1", a.Record.View.Seq, "2", "2026-10-13T00:00:01.001Z", 2)
	c := row(event.Quorum, "n1", a.Record.View.Seq, "2", "2026-10-13T00:00:02Z", 3)
	c.Record.Fields["what"] = "F_PLUS_ONE"
	d := row(event.RoundEnter, "n1", a.Record.View.Seq, "340282366920938463463374607431768211456", "2026-10-13T00:00:02.001Z", 4)
	out := Derive([]logs.Event{a, b, c, d})
	if len(out.Transitions) != 2 || out.Transitions[0].Cause != "timeout" || out.Transitions[0].CauseLine != 1 || out.Transitions[1].Cause != "f_plus_one" || out.Transitions[1].CauseLine != 3 || out.Transitions[1].Confidence != "log_correlated" {
		t.Fatal(out)
	}
	for _, mutate := range []func(*logs.Event){
		func(e *logs.Event) { e.Record.View = &event.View{Seq: "9", Round: "2"} },
		func(e *logs.Event) { e.Run = "other" },
		func(e *logs.Event) { e.Wall = "2026-10-13T00:00:00Z" },
	} {
		x := b
		mutate(&x)
		out = Derive([]logs.Event{a, x})
		if out.Transitions[0].Cause != "unknown" {
			t.Fatal("unrelated trigger attached", out)
		}
	}
	// A trigger is consumed only once.
	b2 := b
	b2.Line = 5
	out = Derive([]logs.Event{a, b, b2})
	if out.Transitions[1].Cause != "unknown" {
		t.Fatal(out)
	}
}
func TestDecisionClaimsArePerNodeAndHeight(t *testing.T) {
	a := row(event.NewHead, "n1", "1", "0", "2026-10-13T00:00:01Z", 1)
	b := row(event.NewHead, "n1", "1", "2", "2026-10-13T00:00:01.001Z", 2)
	c := row(event.NewHead, "n2", "1", "1", "2026-10-13T00:00:02Z", 3)
	d := row(event.NewHead, "n1", "2", "", "2026-10-13T00:00:03Z", 4)
	out := Derive([]logs.Event{a, b, c, d})
	if len(out.Decisions) != 2 || out.Decisions[0].Node != "n1" || out.Decisions[0].Round != "2" || out.Decisions[0].Count != 1 || out.Decisions[1].Node != "n2" || out.UnknownDecisions != 1 {
		t.Fatal(out)
	}
}
