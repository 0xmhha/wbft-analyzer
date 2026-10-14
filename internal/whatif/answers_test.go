package whatif

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnswerAPIKeepsFullCoordinatesWithoutArgumentHash(t *testing.T) {
	a := Answer{Writer: "synthetic", Engine: "9007199254740993", Step: "9007199254740994", Call: 1, Kind: 1, Key: "0x" + strings.Repeat("b", 64)}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"engine_run":"9007199254740993"`) || !strings.Contains(string(raw), `"step":"9007199254740994"`) || strings.Contains(string(raw), a.Key) {
		t.Fatal(string(raw))
	}
	var out Answer
	if json.Unmarshal(raw, &out) != nil || out.Engine != a.Engine || out.Step != a.Step || out.Key != "" {
		t.Fatal("stored metadata roundtrip failed", out)
	}
	wire := `{"writer_run":"synthetic","engine_run":9007199254740993,"step":9007199254740994,"call":1,"kind":1,"key":"` + a.Key + `"}`
	if json.Unmarshal([]byte(wire), &out) != nil || out.Engine != a.Engine || out.Key != a.Key {
		t.Fatal("helper coordinate rounded", out)
	}
}
