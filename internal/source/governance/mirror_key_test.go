package governance

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMirrorPreservesReportedEmptyBLSKeys(t *testing.T) {
	a := fixture()
	keys := []string{"0x" + strings.Repeat("aB", 48), "0x"}
	for _, i := range []int{1, len(a.Replies) - 2} {
		v := resultMap(t, &a, i)
		v["validators"] = []string{testAddr, "0x" + strings.Repeat("4", 40)}
		v["blsPublicKeys"] = keys
		replaceResult(&a, i, v)
	}
	snapshot, err := Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{1, len(snapshot.Calls) - 2} {
		call := snapshot.Calls[i]
		var m Mirror
		if err := json.Unmarshal(call.Data, &m); err != nil {
			t.Fatal(err)
		}
		if call.Status != "available" || len(m.BLSKeys) != 2 || m.BLSKeys[0] != strings.ToLower(keys[0]) || m.BLSKeys[1] != "0x" || len(m.Validators) != 2 {
			t.Fatalf("reported key position or absence changed: %+v", m)
		}
	}
}

func TestMirrorStillRejectsMalformedBLSKeys(t *testing.T) {
	for _, key := range []any{"", "0X", "0x0", "0x00", "0x" + strings.Repeat("1", 94), "0x" + strings.Repeat("1", 98), "0x" + strings.Repeat("z", 96), nil, 0} {
		t.Run(strings.ReplaceAll(string(raw(key)), "\"", ""), func(t *testing.T) {
			a := fixture()
			v := resultMap(t, &a, 1)
			v["blsPublicKeys"] = []any{key}
			replaceResult(&a, 1, v)
			if _, err := Normalize(a); err == nil {
				t.Fatalf("malformed key accepted: %v", key)
			}
		})
	}
}
