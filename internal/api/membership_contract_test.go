package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
)

func TestMembershipRequestContractRequiresExplicitUnmeasuredInputs(t *testing.T) {
	s := loadSpec(t)
	raw := `{"kind":"synthetic_membership","from_ns":0,"to_ns":60000000000,"membership":{"policy":"merge","nodes":[{"alias":"new-test","model":"unmeasured_compat","start_ns":"0","timing":{"request_timeout_seconds":"2","block_period_seconds":"1","max_request_timeout_seconds":"0"},"build_delay":[{"ns":"0"}],"import_delay":[{"ns":"0"}]}],"links":[],"epochs":[{"block":"4","candidates":[0,1,2,3,4]}]}}`
	ref := map[string]any{"$ref": "#/components/schemas/ScenarioNetworkChange"}
	var value any
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if err := s.check(value, ref, "$"); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{`"start_ns":"0"`, `"start_ns":0`}, {`,"max_request_timeout_seconds":"0"`, ``}, {`"build_delay":[{"ns":"0"}]`, `"build_delay":[]`}, {`"nodes":[`, `"extra":true,"nodes":[`}, {`"model":"unmeasured_compat"`, `"model":"unmeasured_compat","private_key":"x"`}} {
		bad := strings.Replace(raw, pair[0], pair[1], 1)
		if bad == raw {
			t.Fatal("mutation did not apply", pair)
		}
		decoder = json.NewDecoder(bytes.NewBufferString(bad))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		if err := s.check(value, ref, "$"); err == nil {
			t.Fatal("schema admitted missing or imprecise synthetic configuration", pair)
		}
		var decoded scenario.NetworkChange
		if json.Unmarshal([]byte(bad), &decoded) == nil {
			t.Fatal("runtime admitted missing or imprecise synthetic configuration", pair)
		}
	}
}
