package whatif

import (
	"encoding/json"
	"testing"
)

func TestPolicyRejectsRoundedUnknownDuplicateAndOverflowValues(t *testing.T) {
	for _, raw := range []string{`{}`, `{"request_timeout_seconds":"1","max_request_timeout_seconds":null}`, `null`, `{"request_timeout_seconds":1}`, `{"request_timeout_seconds":"0"}`, `{"request_timeout_seconds":"01"}`, `{"request_timeout_seconds":"9223372037"}`, `{"request_timeout_seconds":"1","request_timeout_seconds":"2"}`, `{"request_timeout_seconds":"1","other":"2"}`, `{"request_timeout_seconds":null}`, `{"max_request_timeout_seconds":"1"} {}`} {
		var policy Policy
		if json.Unmarshal([]byte(raw), &policy) == nil {
			t.Fatal("invalid policy accepted", raw)
		}
	}
	var first, second Policy
	if json.Unmarshal([]byte(`{"request_timeout_seconds":"2","max_request_timeout_seconds":"0"}`), &first) != nil || json.Unmarshal([]byte(`{"max_request_timeout_seconds":"0","request_timeout_seconds":"2"}`), &second) != nil {
		t.Fatal("valid policy refused")
	}
	a, ha, err := first.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b, hb, err := second.Canonical()
	if err != nil || string(a) != string(b) || ha != hb {
		t.Fatal("equivalent policies not canonical")
	}
}
