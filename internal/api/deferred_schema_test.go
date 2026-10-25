package api

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func TestDeferredSourceSchemaPreservesExactScope(t *testing.T) {
	doc, err := Document()
	if err != nil {
		t.Fatal(err)
	}
	var document spec
	if err := json.Unmarshal(doc, &document); err != nil {
		t.Fatal(err)
	}
	schema, err := document.answerSchema("GET", "/v1/networks/1/datasets/2/messages/source", 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []messages.Record{
		{Input: "normal", File: "00000000000000000001.wal", Ordinal: 1, Seq: "1", Node: "node", Run: "writer", Type: "segment", Observation: &messages.ObservationProfile{Version: "1", PolicyDigest: "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Activation: "340282366920938463463374607431768211456", Retention: "340282366920938463463374607431768211456", Window: "2", HistoryWalk: "128", ReplayHeaders: "4", CheckpointStatus: "recorded_requires_chain", Limits: map[string]string{"checkpoint_bytes": "2097152"}}},
		{Input: "normal", File: "00000000000000000001.wal", Ordinal: 1, Seq: "1", Node: "node", Run: "second-writer", Type: "step", InputKind: "deferred_message", DeferredOrigin: &messages.DeferredEvidence{Origin: messages.DeferredOrigin{WriterRun: "first-writer", CaptureID: "9007199254740993"}, Status: "unavailable", Reason: "missing_capture"}},
		{Input: "normal", File: "00000000000000000001.wal", Ordinal: 1, Seq: "1", Node: "node", Run: "second-writer", Type: "segment", NextHeight: &messages.ReceiveProfile{Version: "1", Entries: "18446744073709551615", Bytes: "9007199254740993", PerPeer: "4", PerSource: "3"}},
	} {
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		if err := document.check(value, schema, "$"); err != nil {
			t.Fatal(err)
		}
		var restored messages.Record
		if err := json.Unmarshal(raw, &restored); err != nil || !reflect.DeepEqual(record, restored) {
			t.Fatalf("writer/capture/uint64 scope changed: %v", err)
		}
	}
}
