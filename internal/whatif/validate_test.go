package whatif

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGeneratedEvidenceKeepsIndependentExecutionAndNullableSource(t *testing.T) {
	height, round := "9007199254740993", "9007199254740994"
	s := Step{Execution: "2", Input: "backlog", Cause: &Source{Writer: "synthetic", Engine: "1", Step: "1", Ordinal: "3"}, Mono: "0", Parent: "1", ArmExecution: "0", Generated: true, Counterfactual: true, Model: Model, Digest: "0x" + strings.Repeat("a", 64), State: State{Running: true, Height: &height, Round: &round, Name: "Prepared"}}
	if err := s.Validate(1); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"source_input":null`) || !strings.Contains(string(raw), `"height":"9007199254740993"`) {
		t.Fatal(string(raw))
	}
	for _, variant := range []string{"fake_source", "skipped_execution", "rounded_height", "stopped_view", "different_model", "self_parent", "comparable_generated", "invalid_question"} {
		c := s
		switch variant {
		case "fake_source":
			c.Source = &Source{Writer: "synthetic", Engine: "1", Step: "1", Ordinal: "1"}
		case "skipped_execution":
			c.Execution = "3"
		case "rounded_height":
			v := "09"
			c.State.Height = &v
		case "stopped_view":
			c.State.Running = false
		case "different_model":
			c.Model = "unknown"
		case "self_parent":
			c.Parent = "2"
		case "comparable_generated":
			c.Comparable = true
		case "invalid_question":
			c.Questions = []Question{{Source: Source{}, Output: "1"}}
		}
		if c.Validate(1) == nil {
			t.Fatal("invalid evidence accepted", variant)
		}
	}
	s.State = State{}
	if s.Validate(1) != nil {
		t.Fatal("stopped state acquired a fabricated view")
	}
}
