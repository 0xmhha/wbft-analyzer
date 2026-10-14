package events

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSealingStageKeepsExactActorIdentityAndRejectsUnknownFields(t *testing.T) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{"kind":"SIM_SEALING_STAGE","actor":"seal","stage":"result_selected","work_id":"work-18446744073709551615","commit_id":"commit-9007199254740993","request_height":"18446744073709551617","request_round":"18446744073709551616","cancelled":true,"private_value":{"text":"secret"}}`), &raw); err != nil {
		t.Fatal(err)
	}
	fields := Metadata(raw)
	for _, key := range []string{"actor", "stage", "work_id", "commit_id", "request_height", "request_round"} {
		var want string
		_ = json.Unmarshal(raw[key], &want)
		if fields[key] != want {
			t.Fatal(key, fields[key], want)
		}
	}
	if fields["cancelled"] != true {
		t.Fatal(fields)
	}
	encoded, _ := json.Marshal(fields)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("arbitrary application field persisted")
	}
	var flat map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &flat)
	flat["kind"] = json.RawMessage(`"SIM_SEALING_STAGE"`)
	if !reflect.DeepEqual(fields, Metadata(flat)) {
		t.Fatal("actor observation changed at persistence")
	}
	for _, value := range []string{`"result_selected result_sent"`, `"accepted"`, `"unknown"`} {
		raw["stage"] = json.RawMessage(value)
		if Metadata(raw)["actor"] != nil {
			t.Fatal("invalid actor-stage combination accepted", value)
		}
	}
	raw["kind"] = json.RawMessage(`"STATE"`)
	raw["stage"] = json.RawMessage(`"result_selected"`)
	if Metadata(raw)["work_id"] != nil {
		t.Fatal("actor identity crossed into consensus state")
	}
}
