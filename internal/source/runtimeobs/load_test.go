package runtimeobs

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizedRuntimeOmitsPathsAndKeepsExactNumericStrings(t *testing.T) {
	c, e := Load("testdata/synthetic.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Validate(); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "synthetic.jsonl") || !strings.Contains(string(b), `"id":"18446744073709551615"`) || c.Points[0].Config.Height != "18446744073709551616" {
		t.Fatal(string(b))
	}
	c.RuntimeModelComplete = true
	if c.Validate() == nil {
		t.Fatal("invented model completeness allowed")
	}
}
