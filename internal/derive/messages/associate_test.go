package messages

import (
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
	"testing"
)

func TestAssociationRequiresOutcomesAndStepClocks(t *testing.T) {
	mono := "7"
	wall := "2020-01-01T00:00:00.000000007Z"
	records := []source.Record{{Input: "j", Node: "a", Run: "same-seed", Type: "outcome", Step: "3", Key: "bytes", Phase: "PREPARE", Outcome: "ACCEPT", Ordinal: 1}, {Input: "j", Node: "a", Run: "same-seed", Type: "step", Step: "3", Wall: wall, Mono: &mono, Ordinal: 2}}
	events := []logs.Event{{Input: "e", Node: "a", Run: "same-seed", Line: 1, Wall: wall, Mono: &mono, Record: event.Record{Src: "event", Kind: event.MsgOutcome, Fields: map[string]any{"step": "3", "dedup_key": "bytes", "phase": "PREPARE", "outcome": "ACCEPT"}}}}
	p := VerifyAssociation(records, events)
	if p.Status != "matched" || p.MatchedAnchors != 1 {
		t.Fatal(p)
	}
	events[0].Record.Fields["dedup_key"] = "different-scenario"
	p = VerifyAssociation(records, events)
	if p.Status != "conflict" || p.ConflictingAnchors != 1 {
		t.Fatal("reused run name proved identity", p)
	}
	events[0].Record.Fields["dedup_key"] = "bytes"
	other := "8"
	events[0].Mono = &other
	if p = VerifyAssociation(records, events); p.Status != "conflict" {
		t.Fatal(p)
	}
	events[0].Mono = &mono
	if p = VerifyAssociation(records[:1], events); p.Status != "insufficient" || p.MissingAnchors != 1 {
		t.Fatal(p)
	}
	events = append(events, events[0])
	if p = VerifyAssociation(records, events); p.Status != "conflict" {
		t.Fatal("duplicate outcome disappeared", p)
	}
}

func TestAssociatedSourcesExcludeUnverifiedRuns(t *testing.T) {
	mono := "7"
	wall := "2020-01-01T00:00:00.000000007Z"
	rs := []source.Record{{Node: "a", Run: "r", Type: "outcome", Step: "1", Key: "k", Phase: "PREPARE", Outcome: "ACCEPT"}, {Node: "a", Run: "r", Type: "step", Step: "1", Wall: wall, Mono: &mono}, {Node: "a", Run: "journal-only", Type: "frame", Key: "k"}}
	es := []logs.Event{{Node: "a", Run: "r", Wall: wall, Mono: &mono, Record: event.Record{Src: "event", Kind: event.MsgOutcome, Fields: map[string]any{"step": "1", "dedup_key": "k", "phase": "PREPARE", "outcome": "ACCEPT"}}}, {Node: "b", Run: "event-only", Record: event.Record{Src: "event", Kind: event.Send}}}
	proof := VerifyAssociation(rs, es)
	if proof.Status != "matched" || proof.JournalOnlyRuns != 1 || proof.EventOnlyRuns != 1 {
		t.Fatal(proof)
	}
	r, e := AssociatedSources(rs, es, proof)
	if len(r) != 2 || len(e) != 1 {
		t.Fatal("unverified runs contributed endpoints", r, e)
	}
	rr, ee := UnassociatedEvidence(rs, es, r, e)
	if len(rr) != 1 || len(ee) != 1 || rr[0].Source.Run != "journal-only" || ee[0].Source.Run != "event-only" || ee[0].Reason != "unassociated_run" {
		t.Fatal("excluded message observations lost their source", rr, ee)
	}
	proof.Status = "partial"
	r, e = AssociatedSources(rs, es, proof)
	if len(r) != 0 || len(e) != 0 {
		t.Fatal("partial proof authorized projection", r, e)
	}
}
