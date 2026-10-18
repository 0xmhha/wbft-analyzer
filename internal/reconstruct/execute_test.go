package reconstruct

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExecuteKeepsInfoOnlySourcesNotPossible(t *testing.T) {
	m := sourceManifest(t, "1", false)
	result, err := Execute(t.Context(), m, "1", "2")
	if err != nil || result.CoreExecuted || len(result.Executions) != 0 || len(result.Heights) != 2 {
		t.Fatal(result, err)
	}
	for _, height := range result.Heights {
		if height.Status != "not_possible" {
			t.Fatal("Info-only source was promoted", height)
		}
	}
	data, err := json.Marshal(result)
	if err != nil || bytes.Contains(data, []byte(m.Log.Path)) {
		t.Fatal("local source path escaped execution projection", err)
	}
}

func TestExecuteRefusesTamperedSourceBeforeReturningAnyProjection(t *testing.T) {
	m := sourceManifest(t, "1", false)
	m.Log.SHA256 = strings.Repeat("f", 64)
	result, err := Execute(t.Context(), m, "1", "1")
	if err == nil || result.ExecutionVersion != "" || len(result.Heights) != 0 || len(result.Executions) != 0 {
		t.Fatal("tampered source produced a partial result", result, err)
	}
}
