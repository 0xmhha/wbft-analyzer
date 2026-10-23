package events

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func cacheStart(t *testing.T, active bool) []byte {
	t.Helper()
	var raw bytes.Buffer
	w := event.NewWriter(&raw, types.Address{19: 1}, "policy-start")
	if err := w.Write(event.Record{Kind: event.NodeStart, Fields: map[string]any{
		"impl": "wbft", "mode": "standalone", "profile": "compat", "sign_floor": nil,
		"wal_recovery": map[string]any{"records": 0, "torn_bytes": 0, "corrupted": 0},
		"transport_cache": map[string]any{"profile": transport.CachePolicyProfile, "active": active,
			"limits": transport.CachePolicyLimits{ReceivePending: 9007199254740993, ReceivePerPeer: 8, WritePending: 64, WritePerPeer: 16}},
	}}, event.Stamp{Wall: time.Unix(1700000000, 0)}); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func TestTransportCacheStartupMetadataSurvivesPersistence(t *testing.T) {
	for _, active := range []bool{false, true} {
		var rows []logs.Event
		stats, err := Read(context.Background(), bytes.NewReader(cacheStart(t, active)), "0x0000000000000000000000000000000000000001", "policy", func(e logs.Event) error { rows = append(rows, e); return nil })
		if err != nil || stats.Malformed != 0 || len(rows) != 1 {
			t.Fatal("schema-checked startup unavailable", stats, err)
		}
		fields := rows[0].Record.Fields
		d, ok := TransportCacheFromMetadata(fields)
		if !ok || d.Active != active || d.Limits.ReceivePending != 9007199254740993 {
			t.Fatal("exact cache declaration lost", d, ok)
		}
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		var flat map[string]json.RawMessage
		if err := json.Unmarshal(raw, &flat); err != nil {
			t.Fatal(err)
		}
		flat["kind"] = json.RawMessage(`"NODE_START"`)
		again := Metadata(flat)
		if !reflect.DeepEqual(fields, again) {
			t.Fatal("persisting metadata changed the cache declaration", fields, again)
		}
		flat["unrecognized"] = json.RawMessage(`"DO_NOT_PERSIST"`)
		encoded, err := json.Marshal(Metadata(flat))
		if err != nil || bytes.Contains(encoded, []byte("DO_NOT_PERSIST")) {
			t.Fatal("unrecognized metadata retained", err)
		}
	}
}

// The optional input is emitted by the actual SDK stored-home startup test.
// Reading it does not start a node or register any analyzer experiment.
func TestTransportCacheActualStoredStartupEvents(t *testing.T) {
	dir := os.Getenv("WBFT_CACHE_STARTUP_EVENTS_INPUT")
	if dir == "" {
		t.Skip("actual stored-start input not configured")
	}
	starts := 0
	for _, name := range []string{"first.jsonl", "restarted.jsonl"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var first struct {
			Node string `json:"node"`
		}
		if err := json.Unmarshal(bytes.Split(raw, []byte{'\n'})[0], &first); err != nil || first.Node == "" {
			t.Fatal("actual input identity unavailable", err)
		}
		stats, err := Read(context.Background(), bytes.NewReader(raw), first.Node, name, func(e logs.Event) error {
			if e.Record.Kind == event.NodeStart {
				starts++
				d, ok := TransportCacheFromMetadata(e.Record.Fields)
				if !ok || !d.Active || d.Limits != (transport.CachePolicyLimits{ReceivePending: 16, ReceivePerPeer: 8, WritePending: 64, WritePerPeer: 16}) {
					t.Fatal("actual stored-start policy lost", d)
				}
			}
			return nil
		})
		if err != nil || stats.Malformed != 0 || stats.Events == 0 {
			t.Fatal("actual startup stream rejected", name, stats, err)
		}
	}
	if starts != 2 {
		t.Fatal("actual cold and stored restart declarations missing", starts)
	}
	t.Log("actual SDK cold start and stored restart preserved both cache declarations")
}

func TestTransportCacheIncompleteNestedDeclarationHasNoFlatFallback(t *testing.T) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(cacheStart(t, true), &raw); err != nil {
		t.Fatal(err)
	}
	fields := Metadata(raw)
	flat, err := json.Marshal(fields)
	if err != nil || json.Unmarshal(flat, &raw) != nil {
		t.Fatal(err)
	}
	raw["kind"] = json.RawMessage(`"NODE_START"`)
	raw["transport_cache"] = json.RawMessage(`{"profile":"accepted_completed_v1"}`)
	got := Metadata(raw)
	if got["transport_cache_profile"] != "unavailable" || got["transport_cache_active"] != nil {
		t.Fatal("incomplete nested policy borrowed flat fields or lost its declaration", got)
	}
	if _, ok := TransportCacheFromMetadata(got); ok {
		t.Fatal("incomplete nested policy became a supported declaration")
	}
}

func TestTransportCacheUnavailableDeclarationSurvivesPersistence(t *testing.T) {
	for _, declaration := range []string{`null`, `{}`, `{"profile":"future","active":true,"limits":{}}`} {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(cacheStart(t, true), &raw); err != nil {
			t.Fatal(err)
		}
		raw["transport_cache"] = json.RawMessage(declaration)
		for range 2 {
			fields := Metadata(raw)
			if fields["transport_cache_profile"] != "unavailable" {
				t.Fatal("persistence erased the unsupported declaration", fields)
			}
			for key := range fields {
				if strings.HasPrefix(key, "transport_cache_") && key != "transport_cache_profile" {
					t.Fatal("uninterpreted policy supplied a configured value", key)
				}
			}
			encoded, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			raw = nil
			if err := json.Unmarshal(encoded, &raw); err != nil {
				t.Fatal("metadata roundtrip failed", err)
			}
			raw["kind"] = json.RawMessage(`"NODE_START"`)
		}
	}
	var absent map[string]json.RawMessage
	if err := json.Unmarshal(cacheStart(t, true), &absent); err != nil {
		t.Fatal(err)
	}
	delete(absent, "transport_cache")
	if _, exists := Metadata(absent)["transport_cache_profile"]; exists {
		t.Fatal("legacy startup acquired an inferred declaration")
	}
}
