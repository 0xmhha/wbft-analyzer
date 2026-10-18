package observe

import (
	"encoding/json"
	"testing"
)

func TestImprovementSourceMetadata(t *testing.T) {
	for _, source := range []string{"profile", "app", "chain"} {
		t.Run(source, func(t *testing.T) {
			a := fixture()
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(a.Replies[0].Response, &envelope); err != nil {
				t.Fatal(err)
			}
			var info map[string]any
			if err := json.Unmarshal(envelope["result"], &info); err != nil {
				t.Fatal(err)
			}
			info["improvements"] = []map[string]string{{"name": "example-rule", "source": source}}
			info["ruleActivations"] = map[string]string{"example-rule": "8"}
			a.Replies[0] = reply("wbft_nodeInfo", []string{}, info)
			snapshot, err := Normalize(a)
			if err != nil {
				t.Fatalf("supported source rejected: %v", err)
			}
			if len(snapshot.Node.Improvements) != 1 || snapshot.Node.Improvements[0].Name != "example-rule" || snapshot.Node.Improvements[0].Source != source {
				t.Fatal("node metadata source changed", snapshot.Node.Improvements)
			}
			var retained struct {
				Improvements []struct {
					Name   string `json:"name"`
					Source string `json:"source"`
				} `json:"improvements"`
			}
			if err := json.Unmarshal(snapshot.Calls[0].Data, &retained); err != nil {
				t.Fatal(err)
			}
			if len(retained.Improvements) != 1 || retained.Improvements[0].Source != source {
				t.Fatal("original call source changed", retained)
			}
		})
	}
	for _, source := range []string{"", "other", "CHAIN", "profile/chain"} {
		a := fixture()
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(a.Replies[0].Response, &envelope); err != nil {
			t.Fatal(err)
		}
		var info map[string]any
		if err := json.Unmarshal(envelope["result"], &info); err != nil {
			t.Fatal(err)
		}
		info["improvements"] = []map[string]string{{"name": "example-rule", "source": source}}
		a.Replies[0] = reply("wbft_nodeInfo", []string{}, info)
		if _, err := Normalize(a); err == nil {
			t.Fatalf("unknown source %q accepted", source)
		}
	}
}
