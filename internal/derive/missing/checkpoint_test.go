package missing

import (
	"fmt"
	"testing"

	derived "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
)

func checkpointFixture(t *testing.T) ([]Height, []logs.Event, []source.Record, []Input) {
	t.Helper()
	before, target, after := baseHeight(), baseHeight(), baseHeight()
	before.Index, before.Number = "0", "0"
	target.Index, target.Number = "2", "2"
	after.Index, after.Number, after.Hash = "3", "3", "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	rows := []logs.Event{
		native(address(1), 1, event.NodeStart, "", "", map[string]any{"validator": true}),
		native(address(1), 2, event.RoundEnter, "1", "0", nil),
		native(address(1), 3, event.MsgOutcome, "1", "0", map[string]any{"step": "2", "code": "19", "dedup_key": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "source": address(2), "outcome": "ACCEPT"}),
		native(address(1), 4, event.NewHead, "3", "0", map[string]any{"hash": after.Hash}),
		native(address(1), 5, event.NodeStop, "", "", nil),
	}
	for i, mono := range []string{"1", "2", "20", "30", "40"} {
		x := mono
		rows[i].Mono = &x
	}
	mono1, mono2 := "10", "20"
	records := []source.Record{
		{Input: "journal", File: "synthetic.wal", Ordinal: 1, Seq: "1", Node: address(1), Run: "run", Type: "segment"},
		{Input: "journal", File: "synthetic.wal", Ordinal: 2, Seq: "2", Node: address(1), Run: "run", Type: "step", Step: "1", ClockSource: "recorded", Wall: rows[0].Wall, Mono: &mono1, HeadNumber: "0", HeadHash: before.Hash},
		{Input: "journal", File: "synthetic.wal", Ordinal: 3, Seq: "3", Node: address(1), Run: "run", Type: "outcome", Step: "2", Key: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: "PREPARE", Outcome: "ACCEPT"},
		{Input: "journal", File: "synthetic.wal", Ordinal: 4, Seq: "4", Node: address(1), Run: "run", Type: "step", Step: "2", ClockSource: "recorded", Wall: rows[0].Wall, Mono: &mono2},
	}
	if proof := derived.VerifyAssociation(records, rows); proof.Status != "matched" {
		t.Fatal("invalid fixture association", proof)
	}
	return []Height{before, target, after}, rows, records, []Input{{ID: address(1), Complete: true}}
}

func checkpointCell(t *testing.T, heights []Height, rows []logs.Event, records []source.Record, inputs []Input) Cell {
	t.Helper()
	cells, err := BuildRange(heights, rows, records, inputs, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cells {
		if c.Validator == address(1) && c.Phase == "PREPARE" {
			return c
		}
	}
	t.Fatal("target cell missing")
	return Cell{}
}

func TestVerifiedJournalCheckpointBracketsRestartCatchup(t *testing.T) {
	h, e, r, i := checkpointFixture(t)
	if c := checkpointCell(t, h, e, nil, i); c.Class != "UNKNOWN" {
		t.Fatal("event-only source lacks the initial head", c)
	}
	c := checkpointCell(t, h, e, r, i)
	if c.Class != "NOT_SENT" || c.Reason != "complete_active_event_capture" || c.ReceiverCoverage != 0 {
		t.Fatal("verified startup checkpoint lost", c)
	}
	found := false
	for _, p := range c.Evidence {
		if p.Role == "sender_canonical_head_before" && p.Source.Kind == "message" && p.Source.Input == "journal" && p.Source.File == "synthetic.wal" && p.Source.Ordinal == 2 {
			found = true
		}
	}
	if !found {
		t.Fatal("exact journal checkpoint pointer absent", fmt.Sprint(c.Evidence))
	}
}

func TestCheckpointCannotBorrowIdentityCoverageOrClock(t *testing.T) {
	cases := map[string]func(*[]Height, *[]logs.Event, *[]source.Record, *[]Input){
		"partial association": func(_ *[]Height, e *[]logs.Event, r *[]source.Record, _ *[]Input) {
			extra := native(address(2), 1, event.NodeStart, "", "", map[string]any{"validator": true})
			extra.Input = "other-events"
			extra.Run = "other"
			*e = append(*e, extra)
			seg := (*r)[0]
			seg.Input = "other-journal"
			seg.Node = address(2)
			seg.Run = "other"
			*r = append(*r, seg)
		},
		"foreign canonical hash": func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) { (*r)[1].HeadHash = "foreign" },
		"checkpoint at target": func(h *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) {
			(*r)[1].HeadNumber = "2"
			(*r)[1].HeadHash = (*h)[1].Hash
		},
		"checkpoint fact missing": func(h *[]Height, _ *[]logs.Event, _ *[]source.Record, _ *[]Input) { *h = (*h)[1:] },
		"different run":           func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) { (*r)[1].Run = "other" },
		"different node":          func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) { (*r)[1].Node = address(2) },
		"conflicting association": func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) { (*r)[2].Key = "different" },
		"journal gap": func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) {
			gap := (*r)[0]
			gap.Type = "gap"
			gap.Ordinal = 5
			*r = append(*r, gap)
		},
		"duplicate source position": func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) { *r = append(*r, (*r)[1]) },
		"ambiguous journal input": func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) {
			seg := (*r)[0]
			seg.Input = "second"
			*r = append(*r, seg)
		},
		"ambiguous event input": func(_ *[]Height, e *[]logs.Event, _ *[]source.Record, _ *[]Input) {
			start := (*e)[0]
			start.Input = "second"
			*e = append(*e, start)
		},
		"checkpoint clock absent": func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) { (*r)[1].Mono = nil },
		"checkpoint before start": func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) { x := "0"; (*r)[1].Mono = &x },
		"checkpoint equal head":   func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) { x := "30"; (*r)[1].Mono = &x },
		"checkpoint after head":   func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) { x := "31"; (*r)[1].Mono = &x },
		"unrecorded checkpoint":   func(_ *[]Height, _ *[]logs.Event, r *[]source.Record, _ *[]Input) { (*r)[1].ClockSource = "unknown" },
		"event head clock absent": func(_ *[]Height, e *[]logs.Event, _ *[]source.Record, _ *[]Input) { (*e)[3].Mono = nil },
		"open event capture":      func(_ *[]Height, e *[]logs.Event, _ *[]source.Record, _ *[]Input) { *e = (*e)[:4] },
		"incomplete event input":  func(_ *[]Height, _ *[]logs.Event, _ *[]source.Record, i *[]Input) { (*i)[0].Complete = false },
		"event loss":              func(_ *[]Height, _ *[]logs.Event, _ *[]source.Record, i *[]Input) { (*i)[0].Stats.SequenceGaps = 1 },
		"observer": func(_ *[]Height, e *[]logs.Event, _ *[]source.Record, _ *[]Input) {
			(*e)[0].Record.Fields["validator"] = false
		},
		"opaque send": func(_ *[]Height, e *[]logs.Event, _ *[]source.Record, _ *[]Input) {
			*e = append(*e, native(address(1), 6, event.Send, "", "", map[string]any{"code": "19", "cause": "broadcast", "dedup_key": "unknown"}))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			h, e, r, i := checkpointFixture(t)
			change(&h, &e, &r, &i)
			if c := checkpointCell(t, h, e, r, i); c.Class != "UNKNOWN" {
				t.Fatal("invalid source became absence", c)
			}
		})
	}
}
