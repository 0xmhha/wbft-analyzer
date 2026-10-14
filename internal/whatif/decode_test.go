package whatif

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeStepRejectsUnknownPayloadRoundedCoordinatesAndTrailingData(t *testing.T) {
	s := Step{Execution: "1", Mono: "0", Parent: "0", ArmExecution: "0", Source: &Source{Writer: "synthetic", Engine: "1", Step: "1", Ordinal: "3"}, Input: "start", Digest: "0x" + strings.Repeat("a", 64), Comparable: true, Counterfactual: true, Model: Model}
	raw, err := json.Marshal(struct {
		Type string `json:"type"`
		ID   uint64 `json:"id"`
		Step
	}{Type: "timed_step", ID: 1, Step: s})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeStep(raw, 0); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		string(raw) + " {}",
		strings.Replace(string(raw), `"execution_state":{"running":false,"height":null,"round":null},`, "", 1),
		strings.Replace(string(raw), `"execution_state":{"running":false,"height":null,"round":null}`, `"execution_state":null`, 1),
		strings.Replace(string(raw), `"running":false,`, "", 1),
		strings.Replace(string(raw), `"running":false`, `"running":null`, 1),
		strings.Replace(string(raw), `"id":1`, `"id":2`, 1),
		strings.Replace(string(raw), `"type":"timed_step"`, `"type":"step"`, 1),
		strings.Replace(string(raw), `"execution_step":"1"`, `"execution_step":"2","execution_step":"1"`, 1),
		strings.Replace(string(raw), `"running":false`, `"running":true,"running":false`, 1),
		strings.Replace(string(raw), `"execution_step":"1"`, `"execution_step":1`, 1),
		strings.Replace(string(raw), `"execution_step":"1"`, `"execution_step":"01"`, 1),
		strings.Replace(string(raw), `"execution_step":"1"`, `"payload":"secret","execution_step":"1"`, 1),
		strings.Repeat(" ", 65537),
	} {
		if _, err = DecodeStep([]byte(bad), 0); err == nil {
			t.Fatal("invalid helper result accepted")
		}
	}
}
