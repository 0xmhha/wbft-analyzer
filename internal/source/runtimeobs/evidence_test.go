package runtimeobs

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTaskEvidenceKeepsAllOriginalStagesAndLargeIdentity(t *testing.T) {
	stages := []string{"task_offer", "task_received", "seal_enter", "seal_return", "task_sent", "request_post_enter", "request_post_return", "seal_result"}
	c, e := FromReader(strings.NewReader(taskInput(stages)))
	if e != nil || len(c.Tasks) != 1 || c.Tasks[0].ID != "18446744073709551615" || len(c.Tasks[0].Intervals) != 3 || c.Tasks[0].Stages[0].Line != 5 || c.Tasks[0].Stages[0].ID != c.Tasks[0].ID {
		t.Fatal(c, e)
	}
	b, _ := json.Marshal(c.Tasks[0])
	if !strings.Contains(string(b), `"id":"18446744073709551615"`) {
		t.Fatal(string(b))
	}
	c, e = FromReader(strings.NewReader(taskInput(append(stages, "seal_result"))))
	if e != nil || c.Tasks[0].State != "ambiguous" || len(c.Tasks[0].Stages) != 9 || len(c.Tasks[0].Intervals) != 0 {
		t.Fatal("duplicate chosen", c, e)
	}
	old, e := FromReader(strings.NewReader(fixture()))
	if e != nil || len(old.Tasks) != 0 || old.ApplicationRequestCompletionProven {
		t.Fatal("old absence inferred", old, e)
	}
}
func TestTaskIntervalsDoNotCorrectRecordedClocks(t *testing.T) {
	stages := []string{"task_offer", "task_received", "seal_enter", "seal_return", "task_sent", "request_post_enter", "request_post_return", "seal_result"}
	raw := taskInput(stages)
	raw = strings.Replace(raw, `"t_mono_ns":11`, `"t_mono_ns":0`, 1)
	c, e := FromReader(strings.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	for _, x := range c.Tasks[0].Intervals {
		if x.Definition == "seal_entry_to_seal_result" {
			t.Fatal("reversed clock was repaired")
		}
	}
}
