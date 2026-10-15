package events

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
)

func sealingDeclarationFixture() map[string]any {
	return map[string]any{"build_queue": "unbuffered-seal", "assembly_return": "sampled_empty_body", "selection": "actors_to_idle_then_deadline_callbacks_seeded", "running_gate": "at_selection", "commit_capacity": 1, "result_capacity": 10, "head_capacity": 10, "pending_age": 7, "call_return_delay_ns": []string{"0", "9007199254740993", "0"}, "post_delay_ns": []string{"17"}, "assembly_delay_ns": []string{"41", "5"}, "import_delay_ns": []string{"9223372036854775807"}}
}
func TestSealingDeclarationPreservesClosedSourceAndRoundTrip(t *testing.T) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bytes.Split(bytes.TrimSpace(fixture(t)), []byte("\n"))[0], &raw); err != nil {
		t.Fatal(err)
	}
	raw["application_model"], _ = json.Marshal(sealingDeclarationFixture())
	data, _ := json.Marshal(raw)
	rows := []logs.Event{}
	stats, err := Read(context.Background(), bytes.NewReader(data), "0x24667eecdc879d40c9396d604ef787f341fff494", "source", func(row logs.Event) error { rows = append(rows, row); return nil })
	if err != nil || stats.Malformed != 0 || len(rows) != 1 {
		t.Fatal(stats, err, len(rows))
	}
	fields := rows[0].Record.Fields
	declaration, ok := SealingDeclarationFromMetadata(fields)
	if !ok || declaration.ResultCapacity != 10 || !reflect.DeepEqual(declaration.CallReturnDelayNS, []string{"0", "9007199254740993", "0"}) || declaration.ImportDelayNS[0] != "9223372036854775807" {
		t.Fatal(declaration, ok)
	}
	flatBytes, _ := json.Marshal(fields)
	var flat map[string]json.RawMessage
	if err := json.Unmarshal(flatBytes, &flat); err != nil {
		t.Fatal(err)
	}
	flat["kind"] = json.RawMessage(`"NODE_START"`)
	again, ok := SealingDeclarationFromMetadata(Metadata(flat))
	if !ok || !reflect.DeepEqual(declaration, again) {
		t.Fatal("persistence changed declaration", declaration, again, ok)
	}
	if rows[0].Input != "source" || rows[0].Line != 1 || rows[0].Run == "" {
		t.Fatal("lost source identity", rows[0])
	}
	flat["kind"] = json.RawMessage(`"STATE"`)
	if Metadata(flat)["application_build_queue"] != nil {
		t.Fatal("policy leaked outside startup")
	}
}
func TestSealingDeclarationRejectsUnsupportedOrUnboundedInputs(t *testing.T) {
	for _, change := range []func(map[string]any){
		func(m map[string]any) { m["result_capacity"] = 0 }, func(m map[string]any) { m["result_capacity"] = 1025 },
		func(m map[string]any) { m["commit_capacity"] = 2 }, func(m map[string]any) { m["head_capacity"] = 9 },
		func(m map[string]any) { m["pending_age"] = 8 }, func(m map[string]any) { m["running_gate"] = "at_return" },
		func(m map[string]any) { m["selection"] = "timestamp" }, func(m map[string]any) { m["done_result"] = "submitted" },
		func(m map[string]any) { delete(m, "assembly_delay_ns") }, func(m map[string]any) { m["post_delay_ns"] = []string{} },
		func(m map[string]any) { m["post_delay_ns"] = []string{"-1"} }, func(m map[string]any) { m["post_delay_ns"] = []string{"01"} },
		func(m map[string]any) { m["post_delay_ns"] = []string{"9223372036854775808"} }, func(m map[string]any) { m["post_delay_ns"] = []any{1} },
		func(m map[string]any) { m["post_delay_ns"] = make([]string, 257) }, func(m map[string]any) { m["private_value"] = "secret" },
	} {
		value := sealingDeclarationFixture()
		change(value)
		data, _ := json.Marshal(value)
		raw := map[string]json.RawMessage{"kind": json.RawMessage(`"NODE_START"`), "application_model": data}
		fields := Metadata(raw)
		if fields["application_build_queue"] != nil {
			t.Fatal("unsupported declaration accepted", value, fields)
		}
		encoded, _ := json.Marshal(fields)
		if strings.Contains(string(encoded), "secret") {
			t.Fatal("unexpected nested field persisted")
		}
	}
}
