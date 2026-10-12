package latency

import (
	"math"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

func mark(kind event.Kind, line int64, wall, mono, profile string) logs.Event {
	e := logs.Event{Record: event.Record{Kind: kind, View: &event.View{Seq: "18446744073709551617", Round: "340282366920938463463374607431768211456"}, Fields: map[string]any{}}, Node: "node1", Input: "in", Run: "engine1", Wall: wall, Profile: profile, Line: line}
	if mono != "" {
		e.Mono = &mono
	}
	return e
}
func group(samples []Sample, metric string) Sample {
	for _, s := range samples {
		if s.Metric == metric {
			return s
		}
	}
	return Sample{}
}
func TestPhaseClockAndWBFTBoundaries(t *testing.T) {
	es := []logs.Event{}
	kinds := []event.Kind{event.RoundEnter, event.PreprepareAccept, event.Quorum, event.Quorum, event.FinalizeHandover, event.NewHead}
	for i, k := range kinds {
		e := mark(k, int64(i+1), "2026-10-13T00:00:00Z", []string{"0", "10000000", "30000000", "60000000", "70000000", "100000000"}[i], "wbft@123456789012")
		if i == 2 {
			e.Record.Fields["what"] = "PREPARE"
		}
		if i == 3 {
			e.Record.Fields["what"] = "COMMIT"
		}
		es = append(es, e)
	}
	got := Derive(es, Filter{})
	expected := map[string]float64{"preprepare": .01, "prepare_quorum": .02, "commit_quorum": .03, "commit": .01, "import": .03, "round_to_decision": .07, "round_to_import": .1}
	for metric, v := range expected {
		s := group(got, metric)
		if s.Clock != "monotonic" || s.Status != "valid" || s.Seconds == nil || math.Abs(*s.Seconds-v) > 1e-9 || s.Height != "18446744073709551617" {
			t.Fatal(metric, s)
		}
	}
	// A wall clock regression does not replace the available monotonic clock.
	es[1].Wall = "2026-10-12T00:00:00Z"
	if s := group(Derive(es, Filter{}), "preprepare"); s.Status != "valid" || s.Clock != "monotonic" {
		t.Fatal(s)
	}
	es[1].Mono = nil
	if s := group(Derive(es, Filter{}), "preprepare"); s.Status != "missing_clock" || s.Seconds != nil {
		t.Fatal(s)
	}
}
func TestLegacyDecisionDoesNotInventImport(t *testing.T) {
	es := []logs.Event{mark(event.RoundEnter, 1, "2026-10-13T00:00:00Z", "", "gstable@740526d03"), mark(event.PreprepareAccept, 2, "2026-10-13T00:00:00.01Z", "", "gstable@740526d03"), mark(event.NewHead, 3, "2026-10-13T00:00:00.1Z", "", "gstable@740526d03"), mark(event.FinalizeHandover, 4, "2026-10-13T00:00:00.2Z", "", "gstable@740526d03")}
	got := Derive(es, Filter{})
	s := group(got, "round_to_decision")
	if s.Status != "valid" || s.Clock != "wall" || *s.Seconds != .1 || s.End.Line != 3 {
		t.Fatal(s)
	}
	if s := group(got, "import"); s.Status != "missing_end" || s.Seconds != nil {
		t.Fatal("invented import", s)
	}
	// A negative measurement stays visible, not zero and not a normal sample.
	es[1].Wall = "2026-10-12T23:59:59Z"
	s = group(Derive(es, Filter{}), "preprepare")
	if s.Status != "negative" || s.Seconds == nil || *s.Seconds != -1 {
		t.Fatal(s)
	}
}
func TestPhasesDoNotCrossEngineViewOrInput(t *testing.T) {
	enter := mark(event.RoundEnter, 1, "2026-10-13T00:00:00Z", "", "gstable@740526d03")
	proposal := mark(event.PreprepareAccept, 2, "2026-10-13T00:00:01Z", "", "gstable@740526d03")
	for _, change := range []func(*logs.Event){func(e *logs.Event) { e.Run = "other" }, func(e *logs.Event) { e.Input = "other" }, func(e *logs.Event) { e.Record.View = &event.View{Seq: "7", Round: "0"} }} {
		e := proposal
		change(&e)
		rows := Derive([]logs.Event{enter, e}, Filter{})
		for _, s := range rows {
			if s.Metric == "preprepare" && s.Status == "valid" {
				t.Fatal("unrelated phases joined", s)
			}
		}
	}
	stop := enter
	stop.Record.Kind = event.EngineStop
	stop.Line = 2
	rows := Derive([]logs.Event{enter, stop, proposal}, Filter{})
	for _, s := range rows {
		if s.Metric == "preprepare" && s.Status == "valid" {
			t.Fatal("engine stop ignored")
		}
	}
	from, _ := time.Parse(time.RFC3339, "2026-10-13T00:00:00.5Z")
	to, _ := time.Parse(time.RFC3339, "2026-10-13T00:00:02Z")
	s := group(Derive([]logs.Event{enter, proposal}, Filter{From: from, To: to}), "preprepare")
	if s.Status != "valid" || s.Start.Line != 1 {
		t.Fatal("context omitted", s)
	}
}
func TestStatisticsUseRawSamplesAndKeepMissingNegative(t *testing.T) {
	samples := []Sample{}
	for i := range 19 {
		v := 1.0
		samples = append(samples, Sample{ID: string(rune('a' + i)), Node: "many", Profile: "p", Metric: "preprepare", Clock: "wall", Status: "valid", Seconds: &v})
	}
	large := 100.0
	samples = append(samples, Sample{Node: "one", Profile: "p", Metric: "preprepare", Clock: "wall", Status: "valid", Seconds: &large})
	samples = append(samples, Sample{Node: "many", Profile: "p", Metric: "preprepare", Clock: "wall", Status: "negative", Seconds: ptr(-2)}, Sample{Node: "many", Profile: "p", Metric: "preprepare", Clock: "wall", Status: "missing_end"})
	out := Summarize(samples)
	for _, g := range out.Groups {
		if g.Node == "" {
			if g.Valid != 20 || g.Missing != 1 || g.Negative != 1 || g.Total != 22 || *g.P95 != 1 || *g.P99 != 100 || *g.Mean != 5.95 {
				t.Fatal(g)
			}
			n := int64(0)
			for _, b := range g.Histogram {
				n += b.Count
			}
			if n != 20 {
				t.Fatal("histogram count differs")
			}
		}
	}
	empty := Summarize([]Sample{{Metric: "import", Clock: "wall", Status: "missing_end"}})
	if empty.Groups[0].P50 != nil || empty.Groups[0].Mean != nil {
		t.Fatal("missing became zero")
	}
}

func TestInvalidMonotonicStampAndUnknownProfile(t *testing.T) {
	a := mark(event.RoundEnter, 1, "2026-10-13T00:00:00Z", "0", "wbft@123456789012")
	b := mark(event.PreprepareAccept, 2, "2026-10-13T00:00:01Z", "9223372036854775808", "wbft@123456789012")
	if s := group(Derive([]logs.Event{a, b}, Filter{}), "preprepare"); s.Status != "invalid_clock" || s.Seconds != nil {
		t.Fatal(s)
	}
	a.Profile = "unknown"
	b.Profile = "unknown"
	if xs := Derive([]logs.Event{a, b}, Filter{}); len(xs) != 0 {
		t.Fatal("unknown profile boundaries assumed", xs)
	}
}
