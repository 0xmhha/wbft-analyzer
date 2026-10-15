package api

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
)

func TestOptionalTimingIntegersRemainQuotedAndNonNullable(t *testing.T) {
	s := loadSpec(t)
	values := s.Components.Schemas["ScenarioTimingValues"]
	properties := values["properties"].(map[string]any)
	for _, name := range []string{"request_timeout_seconds", "block_period_seconds", "max_request_timeout_seconds"} {
		field := properties[name].(map[string]any)
		if field["type"] != "string" || field["pattern"] == nil {
			t.Fatal("optional integer string became numeric or nullable", name, field)
		}
	}
	if values["minProperties"] != float64(1) {
		t.Fatal("empty timing values admitted by document")
	}
	zero := uint64(0)
	raw, err := json.Marshal(scenario.TimingValues{MaxRequestTimeoutSeconds: &zero})
	if err != nil || string(raw) != `{"max_request_timeout_seconds":"0"}` {
		t.Fatal("explicit cap removal or inherited omission changed", string(raw), err)
	}
	deadline := int64(math.MaxInt64)
	arm := scenario.SeedTimerArm{Node: 1, Run: "simulated-run", AtNS: 3, DurationMS: 7, DeadlineNS: &deadline, Height: "1", Round: "0"}
	raw, err = json.Marshal(arm)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["deadline_ns"] != "9223372036854775807" {
		t.Fatal("timer deadline lost integer precision", decoded)
	}
	ref := map[string]any{"$ref": "#/components/schemas/ScenarioSeedTimerArm"}
	if err := s.check(decoded, ref, "$"); err != nil {
		t.Fatal(err)
	}
	delete(decoded, "deadline_ns")
	if err := s.check(decoded, ref, "$"); err != nil {
		t.Fatal("WAL-rearmed timer may omit its deadline", err)
	}
	decoded["deadline_ns"] = nil
	if err := s.check(decoded, ref, "$"); err == nil {
		t.Fatal("explicit null deadline admitted")
	}
}
