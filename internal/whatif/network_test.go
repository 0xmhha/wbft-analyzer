package whatif

import (
	"strings"
	"testing"

	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func networkFixture(t *testing.T) (*Evidence, string, string, []source.Record) {
	t.Helper()
	sender, receiver := "0x"+strings.Repeat("1", 40), "0x"+strings.Repeat("2", 40)
	h, r := "1", "0"
	q := Question{Source{"synthetic", "1", "1", "3"}, "1"}
	e, err := NewEvidence([]Source{q.Source})
	if err != nil {
		t.Fatal(err)
	}
	e.actions = map[Question]Action{q: {Output: "1", Kind: "broadcast", SHA256: strings.Repeat("a", 64), Height: &h, Round: &r, Code: "19", Recipients: []string{receiver}, RecipientEvidence: "validator_set", PayloadSHA256: strings.Repeat("b", 64), PayloadEvidence: "recorded_signing_result"}}
	key := "0x" + strings.Repeat("c", 64)
	frames := []source.Record{
		{Input: "sender", File: "00000000000000000000.wal", Ordinal: 4, Seq: "4", Node: sender, Run: "synthetic", Type: "frame", Dir: "out", Peer: receiver, Phase: "PREPARE", PayloadSHA256: strings.Repeat("b", 64), Key: key, Decode: "decoded", Write: "ok", Cause: "broadcast", Wall: "2026-01-01T00:00:00.000000001Z", ClockSource: "recorded"},
		{Input: "receiver", File: "00000000000000000000.wal", Ordinal: 2, Seq: "2", Node: receiver, Run: "receiver-synthetic", Type: "frame", Dir: "in", Peer: sender, Phase: "PREPARE", PayloadSHA256: strings.Repeat("b", 64), Key: key, Decode: "decoded", Wall: "2026-01-01T00:00:00.000000010Z", ClockSource: "recorded"},
	}
	return e, sender, receiver, frames
}

func TestNetworkBindingRequiresExactProducerDirectionalBytesAndFullScope(t *testing.T) {
	e, sender, _, frames := networkFixture(t)
	bindings, err := e.BindNetwork("sender", sender, frames, source.Clock{Model: "shared-host"})
	if err != nil || len(bindings) != 1 || bindings[0].Status != "observed_delivery" || len(bindings[0].Sends) != 1 || len(bindings[0].Receives) != 1 || bindings[0].Arrival.From != "2026-01-01T00:00:00.00000001Z" {
		t.Fatal(bindings, err)
	}
	for _, mutation := range []string{"other_writer", "other_sender", "other_receiver", "other_bytes", "failed_write", "unknown_clock", "repeat_send_outside_window", "repeat_receive", "reused_bytes_producer", "receive_hash_conflict"} {
		t.Run(mutation, func(t *testing.T) {
			e, sender, receiver, records := networkFixture(t)
			clock := source.Clock{Model: "shared-host"}
			switch mutation {
			case "other_writer":
				records[0].Run = "other"
			case "other_sender":
				records[0].Node = receiver
			case "other_receiver":
				records[1].Peer = receiver
			case "other_bytes":
				records[0].PayloadSHA256 = strings.Repeat("d", 64)
			case "failed_write":
				records[0].Write = "error"
			case "unknown_clock":
				clock.Model = "unknown"
			case "repeat_send_outside_window":
				r := records[0]
				r.Ordinal = 99
				r.Seq = "99"
				r.Wall = "2025-01-01T00:00:00Z"
				records = append(records, r)
			case "repeat_receive":
				r := records[1]
				r.Ordinal = 3
				r.Seq = "3"
				records = append(records, r)
			case "reused_bytes_producer":
				for q, a := range e.actions {
					q.Source.Ordinal = "5"
					e.actions[q] = a
					break
				}
			case "receive_hash_conflict":
				records[1].PayloadSHA256 = strings.Repeat("d", 64)
			}
			bs, err := e.BindNetwork("sender", sender, records, clock)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range bs {
				if b.Status == "observed_delivery" || b.Arrival != nil {
					t.Fatal("fabricated delivery accepted", mutation, b)
				}
			}
		})
	}
}

func TestNetworkBindingDistinguishesRelayAndClockUncertainty(t *testing.T) {
	e, sender, _, records := networkFixture(t)
	for q, a := range e.actions {
		a.Kind = "relay"
		a.PayloadEvidence = "core_relay_bytes"
		e.actions[q] = a
	}
	records[0].Cause = "relay"
	bound := int64(1)
	bs, err := e.BindNetwork("sender", sender, records, source.Clock{Model: "ntp", SkewMS: &bound})
	if err != nil || len(bs) != 1 || bs[0].Status != "clock_overlap" || bs[0].Arrival != nil {
		t.Fatal(bs, err)
	}
	bs, err = e.BindNetwork("sender", sender, records, source.Clock{Model: "shared-host"})
	if err != nil || bs[0].Status != "observed_delivery" {
		t.Fatal(bs, err)
	}
}
