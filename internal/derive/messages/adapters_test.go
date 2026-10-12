package messages

import (
	"encoding/json"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
	"reflect"
	"testing"
)

func TestRecordedPeerIsNotRecoveredAuthor(t *testing.T) {
	records := []source.Record{
		{Input: "relay", File: "00000000000000000000.wal", Ordinal: 1, Node: "relay", Run: "r", Seq: "1", Type: "frame", Dir: "out", Peer: "receiver", Signer: "origin", Key: "bytes", Phase: "PREPARE", Height: "1", Round: "0", Wall: "2020-01-01T00:00:00Z", Cause: "relay", Write: "ok"},
		{Input: "receiver", File: "00000000000000000000.wal", Ordinal: 2, Node: "receiver", Run: "r", Seq: "2", Type: "frame", Dir: "in", Peer: "relay", Signer: "origin", Key: "bytes", Phase: "PREPARE", Height: "1", Round: "0", Wall: "2020-01-01T00:00:00.010Z"},
	}
	p := ProjectRecords(records)
	pairs := PairEndpoints(p.Endpoints, Clock{Model: "shared-host"})
	if len(pairs) != 1 || pairs[0].Sender != "relay" || pairs[0].Receiver != "receiver" || pairs[0].Path != "relay" || pairs[0].Status != "valid" {
		t.Fatal(pairs)
	}
	records[1].Peer = ""
	p = ProjectRecords(records)
	pairs = PairEndpoints(p.Endpoints, Clock{Model: "shared-host"})
	if p.Counts["unknown_peer"] != 1 || len(p.Issues) != 1 || pairs[0].Status != "missing_receive" || pairs[0].Send == nil || pairs[0].Seconds != nil {
		t.Fatal(p, pairs)
	}
}

func TestNativeSendWithoutViewAndBroadcastFanout(t *testing.T) {
	lo, hi := "1000000", "11000000"
	send := logs.Event{Record: event.Record{Kind: event.Send, Src: "event", Fields: map[string]any{"code": "19", "dedup_key": "bytes", "cause": "broadcast"}}, Input: "origin", Node: "a", Run: "native", Line: 1, Wall: "2020-01-01T00:00:00Z", Mono: &lo}
	receive := logs.Event{Record: event.Record{Kind: event.MsgOutcome, Src: "event", View: &event.View{Seq: "18446744073709551617", Round: "0"}, Fields: map[string]any{"code": "19", "source": "a", "dedup_key": "bytes", "outcome": "ACCEPT"}}, Input: "b", Node: "b", Run: "native", Line: 2, Wall: "2020-01-01T00:00:00.010Z", Mono: &hi}
	local := receive
	local.Input = "origin"
	local.Node = "a"
	local.Line = 2
	p := ProjectEvents([]logs.Event{send, receive, local})
	pairs := PairEndpoints(p.Endpoints, Clock{Model: "shared-host"})
	if len(pairs) != 2 {
		t.Fatal(pairs)
	}
	for _, x := range pairs {
		if x.Status != "valid" || x.Strength != "node" || x.Height != "18446744073709551617" || x.Send.Kind != "event" || x.Send.Ordinal != 1 {
			t.Fatal(x)
		}
	}
	if pairs[0].Path != "local" || pairs[0].Clock != "monotonic" || pairs[1].Path != "propagation_processing" {
		t.Fatal(pairs)
	}
	// Order of source arrival must not alter fanout or pair identities.
	other := PairEndpoints(ProjectEvents([]logs.Event{local, receive, send}).Endpoints, Clock{Model: "shared-host"})
	if !reflect.DeepEqual(pairs, other) {
		t.Fatal("order-dependent pairing", pairs, other)
	}
}

func TestLegacyAliasesAndWeakUnknownDigest(t *testing.T) {
	send := logs.Event{Record: event.Record{Kind: event.Send, Fields: map[string]any{"address": "a-address", "phase": "PREPARE", "msg.sequence": "1", "msg.round": "0", "msg.source": "zero-before-signing"}}, Input: "a", Node: "a", Run: "r", Line: 1, Wall: "2020-01-01T00:00:00Z"}
	receive := logs.Event{Record: event.Record{Kind: event.MsgOutcome, Fields: map[string]any{"address": "b-address", "phase": "PREPARE", "msg.sequence": "1", "msg.round": "0", "msg.source": "a-address", "digest": "known"}}, Input: "b", Node: "b", Run: "r", Line: 1, Wall: "2020-01-01T00:00:00.010Z"}
	p := ProjectEvents([]logs.Event{send, receive})
	pairs := PairEndpoints(p.Endpoints, Clock{Model: "shared-host"})
	found := false
	for _, x := range pairs {
		if x.Receiver == "b" {
			found = true
			if x.Status != "valid" || x.Strength != "key" || x.Path != "propagation_processing" {
				t.Fatal(x)
			}
		}
	}
	if !found {
		t.Fatal(pairs)
	}
	// A validator-related addr is not the logger's self identity.
	other := logs.Event{Record: event.Record{Kind: event.Health, Fields: map[string]any{"addr": "a-address"}}, Node: "b", Input: "b", Line: 3}
	contaminated := ProjectEvents([]logs.Event{send, receive, other})
	if contaminated.Counts["unknown_origin"] != 0 {
		t.Fatal("validator addr replaced logger identity", contaminated)
	}
	receive.Record.Fields["msg.source"] = "unmapped"
	p = ProjectEvents([]logs.Event{send, receive})
	if p.Counts["unknown_origin"] != 1 {
		t.Fatal(p)
	}
	receive.Record.Fields["msg.source"] = "a-address"
	receive.Record.Fields["phase"] = "PRE-PREPARE"
	p = ProjectEvents([]logs.Event{send, receive})
	if p.Counts["unobserved_preprepare_receive"] != 1 {
		t.Fatal(p)
	}
}

func TestNativeChecksumAddressAndRelayProcessingPeer(t *testing.T) {
	origin := "0x000000000000000000000000000000000000000a"
	relay := "0x000000000000000000000000000000000000000b"
	recv := "0x000000000000000000000000000000000000000c"
	send := logs.Event{Record: event.Record{Kind: event.Send, Src: "event", Fields: map[string]any{"code": "19", "dedup_key": "bytes", "cause": "relay"}}, Input: "relay", Node: "0x000000000000000000000000000000000000000B", Run: "r", Line: 1, Wall: "2020-01-01T00:00:00Z"}
	received := logs.Event{Record: event.Record{Kind: event.MsgOutcome, Src: "event", View: &event.View{Seq: "1", Round: "0"}, Fields: map[string]any{"code": "19", "dedup_key": "bytes", "source": origin, "peer": relay}}, Input: "received", Node: recv, Run: "r", Line: 1, Wall: "2020-01-01T00:00:00.010Z"}
	projected := ProjectEvents([]logs.Event{send, received})
	pairs := PairEndpoints(projected.Endpoints, Clock{Model: "shared-host"})
	found := false
	for _, p := range pairs {
		if p.Receiver == recv {
			found = true
			if p.Sender != send.Node || p.Path != "propagation_processing" || p.Status != "valid" || p.Strength != "node" {
				t.Fatal(p)
			}
		}
	}
	if !found || projected.Counts["unknown_origin"] != 0 {
		t.Fatal(projected, pairs)
	}
}

func TestConflictingStrongViewsAndMissingEvidence(t *testing.T) {
	a := endpoint("send", "a", "b", "1", "bytes", 0)
	b := endpoint("receive", "a", "b", "2", "bytes", 1)
	p := PairEndpoints([]Endpoint{a, b}, Clock{Model: "shared-host"})
	if len(p) != 1 || p[0].Status != "ambiguous" || p[0].Seconds != nil || len(p[0].Candidates) != 2 || p[0].Height != "" || len(p[0].Views) != 2 {
		t.Fatal(p)
	}
	a.Height = ""
	a.Round = ""
	p = PairEndpoints([]Endpoint{a, b}, Clock{Model: "shared-host"})
	if p[0].Status != "valid" || p[0].Height != "2" {
		t.Fatal(p)
	}
	p = PairEndpoints([]Endpoint{b}, Clock{Model: "shared-host"})
	raw, _ := json.Marshal(p)
	if p[0].Status != "missing_send" || p[0].Receive == nil || len(raw) == 0 {
		t.Fatal(p)
	}
}

func TestRawSampleOverallAndSeparatedEvidenceDimensions(t *testing.T) {
	pairs := []Pair{}
	one, ten := 1.0, 10.0
	for i := 0; i < 100; i++ {
		pairs = append(pairs, Pair{Sender: "a", Receiver: "b", Phase: "PREPARE", Strength: "link", Path: "direct", Clock: "shared-host", Status: "valid", Seconds: &one})
	}
	pairs = append(pairs, Pair{Sender: "b", Receiver: "a", Phase: "PREPARE", Strength: "link", Path: "direct", Clock: "shared-host", Status: "valid", Seconds: &ten})
	pairs = append(pairs, Pair{Sender: "a", Receiver: "b", Phase: "PREPARE", Strength: "key", Path: "propagation_processing", Clock: "unknown", Status: "unknown_clock", RawSeconds: &ten})
	summary := Summarize(pairs)
	directions := 0
	overall := false
	unknown := false
	for _, g := range summary.Groups {
		if g.Key.Scope == "direction" && g.Key.Strength == "link" {
			directions++
			if g.Key.Sender == "b" && *g.Distribution.P95 != 10 {
				t.Fatal(g)
			}
		}
		if g.Key.Scope == "overall" && g.Key.Strength == "link" {
			overall = true
			if g.Distribution.Valid != 101 || *g.Distribution.P95 != 1 || *g.Distribution.Max != 10 {
				t.Fatal(g)
			}
			total := int64(0)
			for _, b := range g.Distribution.Histogram {
				total += b.Count
			}
			if total != 101 {
				t.Fatal(g)
			}
		}
		if g.Key.Scope == "overall" && g.Key.Strength == "key" {
			unknown = true
			if g.Distribution.P95 != nil || g.Distribution.Valid != 0 || g.Statuses["unknown_clock"] != 1 {
				t.Fatal(g)
			}
		}
	}
	if directions != 2 || !overall || !unknown {
		t.Fatal(summary)
	}
}
