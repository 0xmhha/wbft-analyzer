package events

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/proposer-stop.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestPinnedEventStreamPreservesClockStepAndMetadata(t *testing.T) {
	b := fixture(t)
	records := []logs.Event{}
	st, e := Read(context.Background(), bytes.NewReader(b), "0x24667eecdc879d40c9396d604ef787f341fff494", "e1", func(e logs.Event) error { records = append(records, e); return nil })
	if e != nil || st.Malformed != 0 || st.Events == 0 || len(st.SHA256) != 64 {
		t.Fatal(st, e)
	}
	head := false
	timer := false
	state := false
	quorum := false
	for _, e := range records {
		if e.Mono == nil || e.Run != "sim-7-24667eec-1" || e.Record.Src != "event" {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(e.Record.Fields)
		var m map[string]json.RawMessage
		_ = json.Unmarshal(raw, &m)
		m["kind"], _ = json.Marshal(e.Record.Kind)
		again := Metadata(m)
		if string(e.Record.Kind) == "NEW_HEAD" {
			head = true
			if e.Record.View == nil || e.Record.View.Seq != e.Record.Fields["number"] || e.Record.View.Round != e.Record.Fields["round"] {
				t.Fatal("recorded imported height/round unavailable", e)
			}
		}
		if string(e.Record.Kind) == "STATE" {
			state = true
			if again["to"] != e.Record.Fields["to"] {
				t.Fatal("state stripped at persistence", e)
			}
		}
		if string(e.Record.Kind) == "TIMER_ARM" {
			timer = true
			if again["gen"] == nil || again["deadline_mono_ns"] == nil || again["step"] == nil {
				t.Fatal(again)
			}
		}
		if string(e.Record.Kind) == "QUORUM" {
			quorum = true
			if again["count"] == nil || again["quorum"] == nil {
				t.Fatal(again)
			}
		}
	}
	if !head || !timer || !state || !quorum {
		t.Fatal(timer, state, quorum)
	}
}
func TestEventSourcesRejectIdentityAndSequenceOrder(t *testing.T) {
	b := fixture(t)
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	for _, change := range []func([][]byte) [][]byte{
		func(x [][]byte) [][]byte {
			x[1] = bytes.Replace(x[1], []byte(`"seq":1`), []byte(`"seq":0`), 1)
			return x
		},
		func(x [][]byte) [][]byte {
			x[1] = bytes.Replace(x[1], []byte(`"run":"sim-7-24667eec-1"`), []byte(`"run":"another"`), 1)
			return x
		},
	} {
		xs := make([][]byte, len(lines))
		for i, l := range lines {
			xs[i] = bytes.Clone(l)
		}
		st, e := Read(context.Background(), bytes.NewReader(bytes.Join(change(xs), []byte("\n"))), "0x24667eecdc879d40c9396d604ef787f341fff494", "e1", func(logs.Event) error { return nil })
		if e == nil || st.Events > 1 {
			t.Fatal(st, e)
		}
	}
	st, e := Read(context.Background(), bytes.NewReader(b), "other", "e1", func(logs.Event) error { return nil })
	if e == nil || st.Events != 0 {
		t.Fatal(st, e)
	}
	duplicate := bytes.Replace(lines[0], []byte(`"v":1`), []byte(`"v":1,"v":1`), 1)
	st, e = Read(context.Background(), bytes.NewReader(duplicate), "0x24667eecdc879d40c9396d604ef787f341fff494", "e1", func(logs.Event) error { return nil })
	if e != nil || st.Malformed != 1 || st.Events != 0 {
		t.Fatal(st, e)
	}
}
func TestEventMetadataDoesNotKeepPayloadOrArbitraryFields(t *testing.T) {
	var m map[string]json.RawMessage
	_ = json.Unmarshal([]byte(`{"kind":"STATE","from":"AcceptRequest","to":"Prepared","payload":"secret","data":{"key":"secret"},"err":"secret","unexpected":"secret","step":"18446744073709551615","requested_round":"340282366920938463463374607431768211456"}`), &m)
	safe := Metadata(m)
	b, _ := json.Marshal(safe)
	if strings.Contains(string(b), "secret") || safe["step"] != "18446744073709551615" || safe["requested_round"] != "340282366920938463463374607431768211456" {
		t.Fatal(string(b))
	}
}

func TestSequenceGapAndMonoRegressionStayVisible(t *testing.T) {
	lines := bytes.Split(bytes.TrimSpace(fixture(t)), []byte("\n"))
	first := bytes.Replace(lines[0], []byte(`"t_mono_ns":0`), []byte(`"t_mono_ns":100`), 1)
	second := bytes.Replace(lines[1], []byte(`"seq":1`), []byte(`"seq":3`), 1)
	var records []logs.Event
	st, err := Read(context.Background(), bytes.NewReader(bytes.Join([][]byte{first, second}, []byte("\n"))), "0x24667eecdc879d40c9396d604ef787f341fff494", "e1", func(e logs.Event) error { records = append(records, e); return nil })
	if err != nil || st.MonotonicRegressions != 1 || st.SequenceGaps != 1 || st.Events != 2 || *records[0].Mono != "100" || *records[1].Mono != "0" {
		t.Fatal(st, err, records)
	}
}
