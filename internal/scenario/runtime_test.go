package scenario

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/events"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"testing"
	"time"
)

func TestSchemaCheckedStartupPolicyReachesRuntime(t *testing.T) {
	const node = "0x0000000000000000000000000000000000000001"
	const start = `{"v":1,"node":"` + node + `","run":"r1","seq":0,"t_wall":"2020-01-01T00:00:00Z","t_mono_ns":0,"kind":"NODE_START","impl":"wbft","mode":"standalone","profile":"compat","sign_floor":null,"wal_recovery":{"corrupted":0,"records":0,"torn_bytes":0}}`
	for _, tc := range []struct {
		name, extra    string
		known, enabled bool
	}{
		{"enabled_empty_wal", `,"enabled":true,"available":true`, true, true},
		{"disabled", `,"enabled":false,"available":true`, true, false},
		{"missing_dependency", `,"enabled":true,"available":false`, false, false},
		{"older_record", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := fmt.Sprintf(`{"v":1,"node":"%s","run":"r1","seq":1,"t_wall":"2020-01-01T00:00:00Z","t_mono_ns":0,"kind":"ENGINE_START","engine_run":1,"reason":"start","replay":{"records":0,"replayed":false,"stopped":null%s}}`, node, tc.extra)
			var rows []logs.Event
			stats, err := events.Read(context.Background(), strings.NewReader(start+"\n"+engine+"\n"), node, "input", func(x logs.Event) error { rows = append(rows, x); return nil })
			if err != nil || stats.Malformed != 0 || len(rows) != 2 {
				t.Fatal(stats, err, rows)
			}
			got, err := FitRuntime(node, "input", rows, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
			if err != nil || (got.ReplayWAL != nil) != tc.known || tc.known && *got.ReplayWAL != tc.enabled {
				t.Fatal(got, err)
			}
			if len(got.WALPolicies) != 1 || got.WALPolicies[0].Line != 2 || got.WALPolicies[0].Replayed == nil || *got.WALPolicies[0].Replayed {
				t.Fatal("source coordinates or replay outcome lost", got)
			}
		})
	}
}

func TestRuntimeRequiresExplicitFloorAndLifecycle(t *testing.T) {
	origin := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rec := func(kind event.Kind, n int, fields map[string]any) logs.Event {
		return logs.Event{Node: "a", Input: "i", Profile: logs.EventProfile, Run: "r", Line: int64(n + 1), Wall: origin.Add(time.Duration(n) * time.Second).Format(time.RFC3339Nano), Record: event.Record{Kind: kind, Fields: fields}}
	}
	xs := []logs.Event{rec(event.NodeStart, 0, map[string]any{"sign_floor_state": "none"}), rec(event.NodeStop, 2, nil), rec(event.NodeStart, 3, map[string]any{"sign_floor_state": "none"})}
	got, err := FitRuntime("a", "i", xs, origin)
	if err != nil || got.Starts != 2 || got.SignFloor != nil || len(got.Events) != 2 || got.Events[1].Action != "restart" {
		t.Fatalf("runtime %+v %v", got, err)
	}
	xs[0].Record.Fields = nil
	if _, err := FitRuntime("a", "i", xs, origin); err == nil {
		t.Fatal("missing floor inferred as absent")
	}
	xs[0].Record.Fields = map[string]any{"sign_floor_state": "none"}
	xs[1].Wall = origin.Add(4 * time.Second).Format(time.RFC3339Nano)
	if _, err := FitRuntime("a", "i", xs, origin); err == nil {
		t.Fatal("clock regression sorted away")
	}
	if _, err := FitRuntime("a", "i", xs[1:], origin); err == nil {
		t.Fatal("stop without start accepted")
	}
}

func TestRuntimePolicyRequiresRecordedConfigurationForEveryStart(t *testing.T) {
	origin := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	rec := func(kind event.Kind, line int, run string, fields map[string]any) logs.Event {
		return logs.Event{Node: "node", Input: "input", Profile: logs.EventProfile, Run: run, Line: int64(line), Wall: origin.Add(time.Duration(line-1) * time.Millisecond).Format(time.RFC3339Nano), Record: event.Record{Kind: kind, Fields: fields}}
	}
	start := rec(event.NodeStart, 1, "r1", map[string]any{"sign_floor_state": "none"})
	old := rec(event.EngineStart, 2, "r1", map[string]any{"engine_run": "1", "wal_replayed": false, "wal_replay_status": "complete"})
	got, err := FitRuntime("node", "input", []logs.Event{start, old}, origin)
	if err != nil || got.ReplayWAL != nil {
		t.Fatal("no replay result mistaken for disabled policy", err)
	}
	for _, enabled := range []bool{false, true} {
		policy := rec(event.EngineStart, 2, "r1", map[string]any{"engine_run": "1", "wal_replayed": false, "wal_replay_enabled": enabled, "wal_available": true, "wal_replay_status": "complete"})
		got, err := FitRuntime("node", "input", []logs.Event{start, policy}, origin)
		if err != nil || got.ReplayWAL == nil || *got.ReplayWAL != enabled || got.WALPolicies[0].Line != 2 {
			t.Fatal(got, err)
		}
		policy.Record.Fields["wal_available"] = false
		got, err = FitRuntime("node", "input", []logs.Event{start, policy}, origin)
		if err != nil || got.ReplayWAL != nil {
			t.Fatal("missing WAL dependency assumed available", got, err)
		}
	}
	policy := rec(event.EngineStart, 2, "r1", map[string]any{"engine_run": "1", "wal_replay_enabled": true, "wal_available": true, "wal_replay_status": "complete"})
	stopped := rec(event.NodeStop, 3, "r1", nil)
	restart := rec(event.NodeStart, 4, "r2", map[string]any{"sign_floor_state": "none"})
	got, err = FitRuntime("node", "input", []logs.Event{start, policy, stopped, restart}, origin)
	if err != nil || got.ReplayWAL != nil {
		t.Fatal("later incarnation inherited unrecorded policy", got, err)
	}
	wrong := rec(event.EngineStart, 2, "other", policy.Record.Fields)
	got, err = FitRuntime("node", "input", []logs.Event{start, wrong}, origin)
	if err != nil || got.ReplayWAL != nil {
		t.Fatal("another writer proved runtime policy", got, err)
	}
}
