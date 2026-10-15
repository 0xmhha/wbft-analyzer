package jsonmeta

import "testing"

func TestMetadataRejectsDuplicateAndUnboundedDocuments(t *testing.T) {
	for _, raw := range []string{`{"x":1,"x":2}`, `{"x":{"y":1,"y":2}}`, `{"x":1} {"x":2}`, `{"x":null,}`, `[[]`} {
		var dst any
		if Decode([]byte(raw), 4096, false, &dst) == nil {
			t.Fatal("accepted damaged metadata", raw)
		}
	}
	var dst struct {
		X int `json:"x"`
	}
	if Decode([]byte(`{"x":1,"private_field":"discarded"}`), 4096, true, &dst) == nil {
		t.Fatal("strict boundary accepted unknown field")
	}
	if Decode([]byte(`{"x":1,"private_field":"discarded"}`), 4096, false, &dst) != nil || dst.X != 1 {
		t.Fatal("subset projection failed")
	}
	if Decode([]byte(`{"x":1}`), 2, false, &dst) == nil {
		t.Fatal("byte bound ignored")
	}
}
