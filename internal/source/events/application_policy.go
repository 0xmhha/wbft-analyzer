package events

import "encoding/json"

// Only the closed simulator declaration crosses the metadata boundary. The
// flattened form must survive the same sanitizer when persistence reapplies it.
func applicationPolicyMetadata(m map[string]json.RawMessage, out map[string]any) {
	keys := []string{"build_queue", "done_result", "assembly_return", "selection"}
	values := map[string]string{}
	if raw, exists := m["application_model"]; exists {
		if json.Unmarshal(raw, &values) != nil {
			return
		}
	} else {
		for _, k := range keys {
			var text string
			if json.Unmarshal(m["application_"+k], &text) != nil {
				return
			}
			values[k] = text
		}
	}
	if values["build_queue"] != "serial-latest" || values["done_result"] != "failed" && values["done_result"] != "submitted" || values["assembly_return"] != "sampled" || values["selection"] != "callbacks_then_done_then_pending" {
		return
	}
	for _, k := range keys {
		out["application_"+k] = values[k]
	}
}
