package whatif

import (
	"strings"
	"testing"
)

func TestBoundedRequestDecoderKeepsStrictLimitsAndDuplicateRejection(t *testing.T) {
	var value struct {
		Name string `json:"name"`
	}
	raw := []byte(`{"name":"` + strings.Repeat("a", 5000) + `"}`)
	if DecodeJSON(raw, &value) == nil {
		t.Fatal("default request limit expanded")
	}
	if DecodeJSONSize(raw, &value, 8192) != nil || len(value.Name) != 5000 {
		t.Fatal("explicit larger request refused")
	}
	for _, raw := range []string{`{"name":"a","name":"b"}`, `{"name":"a","unknown":1}`, `{"name":"a"} {}`} {
		if DecodeJSONSize([]byte(raw), &value, 8192) == nil {
			t.Fatal("strict metadata boundary weakened", raw)
		}
	}
	for _, limit := range []int{0, -1, 2<<20 + 1, 4096} {
		if DecodeJSONSize(raw, &value, limit) == nil {
			t.Fatal("invalid or exceeded request bound accepted", limit)
		}
	}
}
