package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"os"
	"reflect"
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

func TestNativeAppendRunBoundaryPreservesOriginalLines(t *testing.T) {
	first := `{"v":1,"node":"0x0000000000000000000000000000000000000001","run":"r1","seq":0,"t_wall":"2020-01-01T00:00:00Z","t_mono_ns":100,"kind":"NODE_START","validator":true,"impl":"wbft","mode":"standalone","sign_floor":null,"wal_recovery":{"records":0,"torn_bytes":0,"corrupted":0},"handshake":"start"}`
	second := strings.ReplaceAll(strings.ReplaceAll(first, `"r1"`, `"r2"`), `"t_mono_ns":100`, `"t_mono_ns":0`)
	var rows []logs.Event
	stats, e := Read(context.Background(), strings.NewReader(first+"\n"+second), "0x0000000000000000000000000000000000000001", "events", func(r logs.Event) error { rows = append(rows, r); return nil })
	if e != nil || len(rows) != 2 || rows[1].Line != 2 || rows[1].Run != "r2" || stats.MonotonicRegressions != 0 || stats.SequenceGaps != 0 {
		t.Fatal(stats, rows, e)
	}
	for _, bad := range []string{strings.Replace(second, `"seq":0`, `"seq":1`, 1), second + "\n" + first} {
		if _, e = Read(context.Background(), strings.NewReader(first+"\n"+bad), "0x0000000000000000000000000000000000000001", "events", func(logs.Event) error { return nil }); e == nil {
			t.Fatal("invalid or reused run accepted")
		}
	}
}

func TestSignFloorMetadataIsTypedAndSurvivesPersistence(t *testing.T) {
	var raw map[string]json.RawMessage
	_ = json.Unmarshal([]byte(`{"kind":"NODE_START","sign_floor":{"height":"18446744073709551617","status":"kept","unexpected":"secret"},"payload":"secret"}`), &raw)
	safe := Metadata(raw)
	if safe["sign_floor_height"] != "18446744073709551617" || safe["sign_floor_status"] != "kept" {
		t.Fatal(safe)
	}
	b, _ := json.Marshal(safe)
	if strings.Contains(string(b), "secret") {
		t.Fatal(string(b))
	}
	raw = map[string]json.RawMessage{}
	_ = json.Unmarshal(b, &raw)
	raw["kind"] = json.RawMessage(`"NODE_START"`)
	if again := Metadata(raw); again["sign_floor_height"] != safe["sign_floor_height"] {
		t.Fatal("persistence dropped floor", again)
	}
	raw["sign_floor_status"] = json.RawMessage(`"unknown"`)
	if Metadata(raw)["sign_floor_height"] != nil {
		t.Fatal("invalid floor status preserved")
	}
	raw["kind"] = json.RawMessage(`"HEALTH"`)
	raw["h"] = json.RawMessage(`"18446744073709551617"`)
	if Metadata(raw)["h"] != "18446744073709551617" {
		t.Fatal("health height truncated")
	}
}

func TestNativeHealthConditionsSurviveMetadataBoundaries(t *testing.T) {
	for _, what := range []string{"head_mismatch", "peer_inbound_overflow", "peer_inbound_disconnect", "privval_refusal", "sign_floor_skip",
		"snapshot_missing_at_preprepare", "snapshot_missing_at_local_reproposal", "snapshot_missing_at_head", "consensus_halted", "disconnect", "same_block_transitions"} {
		t.Run(what, func(t *testing.T) {
			var raw map[string]json.RawMessage
			err := json.Unmarshal([]byte(`{"kind":"HEALTH","what":"`+what+`","h":"18446744073709551617","error":"private text"}`), &raw)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				safe := Metadata(raw)
				if safe["what"] != what || safe["h"] != "18446744073709551617" || safe["error"] != nil {
					t.Fatal(safe)
				}
				b, err := json.Marshal(safe)
				if err != nil {
					t.Fatal(err)
				}
				raw = map[string]json.RawMessage{}
				if err = json.Unmarshal(b, &raw); err != nil {
					t.Fatal(err)
				}
				raw["kind"] = json.RawMessage(`"HEALTH"`)
			}
		})
	}
	for _, pair := range [][2]string{{"HEALTH", "PREPARE"}, {"HEALTH", "unrecognized"}, {"QUORUM", "sign_floor_skip"}, {"SEND", "peer_inbound_overflow"}} {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(`{"kind":"`+pair[0]+`","what":"`+pair[1]+`"}`), &raw); err != nil {
			t.Fatal(err)
		}
		if safe := Metadata(raw); safe["what"] != nil {
			t.Fatal("condition crossed kind or allowlist", safe)
		}
	}
}

func TestExplicitAbsentSignFloorSurvivesMetadataBoundary(t *testing.T) {
	raw := map[string]json.RawMessage{"kind": json.RawMessage(`"NODE_START"`), "sign_floor": json.RawMessage(`null`)}
	got := Metadata(raw)
	if got["sign_floor_state"] != "none" {
		t.Fatal("explicit null floor lost")
	}
	delete(raw, "sign_floor")
	if Metadata(raw)["sign_floor_state"] != nil {
		t.Fatal("missing floor fabricated")
	}
	raw["sign_floor_state"] = json.RawMessage(`"none"`)
	if Metadata(raw)["sign_floor_state"] != "none" {
		t.Fatal("persisted state lost")
	}
}

func TestReplayPolicyMetadataDistinguishesConfigurationAndResult(t *testing.T) {
	cases := []struct {
		raw     string
		enabled any
	}{{`{"records":0,"stopped":null,"replayed":false}`, nil}, {`{"records":0,"stopped":null,"replayed":false,"enabled":true,"available":true}`, true}, {`{"records":0,"stopped":null,"replayed":false,"enabled":false,"available":true}`, false}, {`{"records":0,"stopped":"private path or error","replayed":false,"enabled":true,"available":false}`, true}}
	for _, tc := range cases {
		raw := map[string]json.RawMessage{"kind": json.RawMessage(`"ENGINE_START"`), "replay": json.RawMessage(tc.raw)}
		got := Metadata(raw)
		if got["wal_replay_enabled"] != tc.enabled || got["wal_replayed"] != false {
			t.Fatal(got)
		}
		if strings.Contains(fmt.Sprint(got), "private path") {
			t.Fatal("raw replay error retained")
		}
		for i := 0; i < 2; i++ {
			bytes, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			raw = map[string]json.RawMessage{}
			if err = json.Unmarshal(bytes, &raw); err != nil {
				t.Fatal(err)
			}
			raw["kind"] = json.RawMessage(`"ENGINE_START"`)
			again := Metadata(raw)
			if !reflect.DeepEqual(got, again) {
				t.Fatalf("metadata reapplication changed policy %+v %+v", got, again)
			}
			got = again
		}
	}
	raw := map[string]json.RawMessage{"kind": json.RawMessage(`"ENGINE_START"`), "replay": json.RawMessage(`{"enabled":null,"available":"true"}`)}
	if got := Metadata(raw); got["wal_replay_enabled"] != nil || got["wal_available"] != nil {
		t.Fatal("unknown policy defaulted", got)
	}
}

func TestSameBlockTransitionMetadataContext(t *testing.T) {
	for _, height := range []string{"0", "6", "18446744073709551617"} {
		t.Run(height, func(t *testing.T) {
			reason := "2 transitions at block " + height + " retain their configured application order"
			raw, err := json.Marshal(map[string]any{"kind": "HEALTH", "what": "same_block_transitions", "reason": reason, "error": "private text", "payload": map[string]any{"secret": "not metadata"}})
			if err != nil {
				t.Fatal(err)
			}
			var input map[string]json.RawMessage
			if err = json.Unmarshal(raw, &input); err != nil {
				t.Fatal(err)
			}
			safe := Metadata(input)
			if safe["what"] != "same_block_transitions" || safe["h"] != height || safe["count"] != "2" || safe["reason"] != nil || safe["error"] != nil || safe["payload"] != nil {
				t.Fatal(safe)
			}
			raw, err = json.Marshal(safe)
			if err != nil {
				t.Fatal(err)
			}
			input = map[string]json.RawMessage{}
			if err = json.Unmarshal(raw, &input); err != nil {
				t.Fatal(err)
			}
			input["kind"] = json.RawMessage(`"HEALTH"`)
			if again := Metadata(input); !reflect.DeepEqual(safe, again) {
				t.Fatal("structured warning lost on persistence projection", safe, again)
			}
		})
	}
	for _, fields := range []map[string]any{
		{"h": "7"}, {"count": "3"}, {"h": "not a height"}, {"count": -1},
	} {
		fields["kind"], fields["what"], fields["reason"] = "HEALTH", "same_block_transitions", "2 transitions at block 6 retain their configured application order"
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		var input map[string]json.RawMessage
		if err = json.Unmarshal(raw, &input); err != nil {
			t.Fatal(err)
		}
		if safe := Metadata(input); safe["what"] != "same_block_transitions" || safe["h"] != nil || safe["count"] != nil {
			t.Fatal("conflicting warning context retained", safe)
		}
	}

	for _, reason := range []string{
		"private text",
		"2 transitions at block /private/secret retain their configured application order",
		"02 transitions at block 6 retain their configured application order",
		"1 transitions at block 6 retain their configured application order",
		"2 transitions at block -2 retain their configured application order",
		"2 transitions at block 06 retain their configured application order",
		"18446744073709551616 transitions at block 6 retain their configured application order",
		"2 transitions at block " + strings.Repeat("9", 157) + " retain their configured application order",
	} {
		raw, err := json.Marshal(map[string]any{"kind": "HEALTH", "what": "same_block_transitions", "reason": reason})
		if err != nil {
			t.Fatal(err)
		}
		var input map[string]json.RawMessage
		if err = json.Unmarshal(raw, &input); err != nil {
			t.Fatal(err)
		}
		safe := Metadata(input)
		if safe["what"] != "same_block_transitions" || safe["h"] != nil || safe["count"] != nil || safe["reason"] != nil {
			t.Fatal("noncanonical warning context retained", safe)
		}
	}
}
