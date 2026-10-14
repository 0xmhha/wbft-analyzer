package events

import (
	"encoding/json"
	"strconv"
)

// SealingDeclaration preserves the closed scheduler and executor inputs of a
// declared simulator. It is not evidence of a physical executor policy.
type SealingDeclaration struct {
	RunningGate       string   `json:"running_gate"`
	CommitCapacity    int      `json:"commit_capacity"`
	ResultCapacity    int      `json:"result_capacity"`
	HeadCapacity      int      `json:"head_capacity"`
	PendingAge        int      `json:"pending_age"`
	CallReturnDelayNS []string `json:"call_return_delay_ns"`
	PostDelayNS       []string `json:"post_delay_ns"`
	AssemblyDelayNS   []string `json:"assembly_delay_ns"`
	ImportDelayNS     []string `json:"import_delay_ns"`
}

var applicationKeys = []string{"build_queue", "done_result", "assembly_return", "selection", "running_gate", "commit_capacity", "result_capacity", "head_capacity", "pending_age", "call_return_delay_ns", "post_delay_ns", "assembly_delay_ns", "import_delay_ns"}

func policyString(m map[string]json.RawMessage, key, want string) bool {
	var s string
	return json.Unmarshal(m[key], &s) == nil && s == want
}
func policyCount(m map[string]json.RawMessage, key string, min, max int) (int, bool) {
	var n int
	if json.Unmarshal(m[key], &n) != nil || n < min || n > max {
		return 0, false
	}
	return n, true
}
func policyDelays(m map[string]json.RawMessage, key string) ([]string, bool) {
	var values []string
	if json.Unmarshal(m[key], &values) != nil || len(values) < 1 || len(values) > 256 {
		return nil, false
	}
	if !validPolicyDelays(values) {
		return nil, false
	}
	return values, true
}
func validPolicyDelays(values []string) bool {
	if len(values) < 1 || len(values) > 256 {
		return false
	}
	for _, s := range values {
		n, err := strconv.ParseUint(s, 10, 63)
		if err != nil || strconv.FormatUint(n, 10) != s {
			return false
		}
	}
	return true
}

// Valid checks declarations constructed outside the source parser as well.
func (d *SealingDeclaration) Valid() bool {
	return d != nil && d.RunningGate == "at_selection" && d.CommitCapacity == 1 && d.ResultCapacity >= 1 && d.ResultCapacity <= 1024 && d.HeadCapacity == 10 && d.PendingAge == 7 && validPolicyDelays(d.CallReturnDelayNS) && validPolicyDelays(d.PostDelayNS) && validPolicyDelays(d.AssemblyDelayNS) && validPolicyDelays(d.ImportDelayNS)
}

func decodeSealingDeclaration(m map[string]json.RawMessage) (*SealingDeclaration, bool) {
	if len(m) != 12 || !policyString(m, "build_queue", "unbuffered-seal") || !policyString(m, "assembly_return", "sampled_empty_body") || !policyString(m, "selection", "actors_to_idle_then_deadline_callbacks_seeded") || !policyString(m, "running_gate", "at_selection") {
		return nil, false
	}
	d := &SealingDeclaration{RunningGate: "at_selection"}
	var ok bool
	if d.CommitCapacity, ok = policyCount(m, "commit_capacity", 1, 1); !ok {
		return nil, false
	}
	if d.ResultCapacity, ok = policyCount(m, "result_capacity", 1, 1024); !ok {
		return nil, false
	}
	if d.HeadCapacity, ok = policyCount(m, "head_capacity", 10, 10); !ok {
		return nil, false
	}
	if d.PendingAge, ok = policyCount(m, "pending_age", 7, 7); !ok {
		return nil, false
	}
	if d.CallReturnDelayNS, ok = policyDelays(m, "call_return_delay_ns"); !ok {
		return nil, false
	}
	if d.PostDelayNS, ok = policyDelays(m, "post_delay_ns"); !ok {
		return nil, false
	}
	if d.AssemblyDelayNS, ok = policyDelays(m, "assembly_delay_ns"); !ok {
		return nil, false
	}
	if d.ImportDelayNS, ok = policyDelays(m, "import_delay_ns"); !ok {
		return nil, false
	}
	return d, true
}
func flatApplicationPolicy(m map[string]json.RawMessage) map[string]json.RawMessage {
	values := map[string]json.RawMessage{}
	for _, k := range applicationKeys {
		if raw, ok := m["application_"+k]; ok {
			values[k] = raw
		}
	}
	return values
}

// SealingDeclarationFromMetadata rechecks persisted, flattened declarations.
// Arrays retain order and multiplicity because both affect seeded sampling.
func SealingDeclarationFromMetadata(fields map[string]any) (*SealingDeclaration, bool) {
	m := map[string]json.RawMessage{}
	for _, k := range applicationKeys {
		if value, ok := fields["application_"+k]; ok {
			raw, err := json.Marshal(value)
			if err != nil {
				return nil, false
			}
			m[k] = raw
		}
	}
	return decodeSealingDeclaration(m)
}

// Only closed simulator declarations cross the metadata boundary. Their
// flattened forms survive the same sanitizer when persistence reapplies it.
func applicationPolicyMetadata(m map[string]json.RawMessage, out map[string]any) {
	var values map[string]json.RawMessage
	if raw, exists := m["application_model"]; exists {
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return
		}
	} else {
		values = flatApplicationPolicy(m)
	}
	if len(values) == 4 && policyString(values, "build_queue", "serial-latest") && (policyString(values, "done_result", "failed") || policyString(values, "done_result", "submitted")) && policyString(values, "assembly_return", "sampled") && policyString(values, "selection", "callbacks_then_done_then_pending") {
		for _, k := range []string{"build_queue", "done_result", "assembly_return", "selection"} {
			var s string
			_ = json.Unmarshal(values[k], &s)
			out["application_"+k] = s
		}
		return
	}
	d, ok := decodeSealingDeclaration(values)
	if !ok {
		return
	}
	out["application_build_queue"] = "unbuffered-seal"
	out["application_assembly_return"] = "sampled_empty_body"
	out["application_selection"] = "actors_to_idle_then_deadline_callbacks_seeded"
	out["application_running_gate"] = d.RunningGate
	out["application_commit_capacity"], out["application_result_capacity"], out["application_head_capacity"], out["application_pending_age"] = d.CommitCapacity, d.ResultCapacity, d.HeadCapacity, d.PendingAge
	out["application_call_return_delay_ns"], out["application_post_delay_ns"], out["application_assembly_delay_ns"], out["application_import_delay_ns"] = d.CallReturnDelayNS, d.PostDelayNS, d.AssemblyDelayNS, d.ImportDelayNS
}
