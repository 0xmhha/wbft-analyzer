package scenario

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/events"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/event"
)

func engineHistoryFixture(t *testing.T, node string) ([]logs.Event, time.Time) {
	t.Helper()
	origin := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var raw bytes.Buffer
	line := 0
	for _, run := range []string{"first", "second"} {
		for seq, kind := range []event.Kind{event.NodeStart, event.EngineStart, event.EngineStop, event.EngineStart, event.NodeStop, event.EngineStop} {
			line++
			row := map[string]any{"v": 1, "node": node, "run": run, "seq": seq, "t_wall": origin.Add(time.Duration(line) * 10 * time.Millisecond).Format(time.RFC3339Nano), "t_mono_ns": line * 10000000, "kind": kind}
			switch kind {
			case event.NodeStart:
				row["impl"], row["mode"], row["profile"], row["sign_floor"] = "wbft", "standalone", "compat", nil
				row["wal_recovery"] = map[string]any{"records": 0, "corrupted": 0, "torn_bytes": 0}
			case event.EngineStart, event.EngineStop:
				generation := 1
				if seq >= 3 {
					generation = 2
				}
				row["engine_run"], row["reason"] = generation, "operator"
				if kind == event.EngineStart {
					row["reason"] = "start"
					row["replay"] = map[string]any{"enabled": true, "available": true, "records": 0, "replayed": false, "stopped": nil}
				}
			case event.NodeStop:
				row["reason"] = "operator"
			}
			if err := json.NewEncoder(&raw).Encode(row); err != nil {
				t.Fatal(err)
			}
		}
	}
	rows := []logs.Event{}
	stats, err := events.Read(context.Background(), &raw, node, "native", func(x logs.Event) error { rows = append(rows, x); return nil })
	if err != nil || stats.Malformed != 0 || len(rows) != 12 {
		t.Fatal("schema-checked lifecycle fixture", stats, err)
	}
	return rows, origin
}

func TestEngineHistoryBindsEveryGenerationAndSeparatesNodeTeardown(t *testing.T) {
	rows, origin := engineHistoryFixture(t, "0x0000000000000000000000000000000000000001")
	r, err := FitRuntime(rows[0].Node, "native", rows, origin)
	if err != nil || r.EngineHistory == nil || r.EngineHistory.Status != "complete" || !r.EngineStopped || r.Starts != 2 || len(r.WALPolicies) != 4 || r.ReplayWAL == nil || !*r.ReplayWAL || len(r.Events) != 7 {
		t.Fatal("node starts and engine generations were conflated", r, err)
	}
	h := r.EngineHistory
	if len(h.Instances) != 4 || len(h.Actions) != 4 || h.Instances[0].Terminal || !h.Instances[1].Terminal || h.Instances[2].Terminal || !h.Instances[3].Terminal || h.Instances[2].Engine != "1" || h.Instances[2].Run != "second" {
		t.Fatal(h)
	}
	if r.Events[0].Action != sim.ActionEngineStop || r.Events[0].Line != 3 || r.Events[1].Action != sim.ActionEngineStart || r.Events[1].Engine != "2" || r.Events[2].Action != sim.ActionStop || r.Events[3].Action != sim.ActionRestart {
		t.Fatal("source order or source coordinates changed", r.Events)
	}
}

func TestEngineHistoryRefusesAmbiguousMissingAndReversedEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]logs.Event) []logs.Event
	}{
		{"missing_stop", func(xs []logs.Event) []logs.Event { return append(xs[:2], xs[3:]...) }},
		{"duplicate_generation", func(xs []logs.Event) []logs.Event { xs[3].Record.Fields["engine_run"] = "1"; return xs }},
		{"unknown_generation", func(xs []logs.Event) []logs.Event { delete(xs[2].Record.Fields, "engine_run"); return xs }},
		{"wrong_writer", func(xs []logs.Event) []logs.Event { xs[2].Run = "unrelated"; return xs }},
		{"clock_regression", func(xs []logs.Event) []logs.Event { xs[2].Wall = "2025-12-31T23:59:59Z"; return xs }},
		{"unclosed", func(xs []logs.Event) []logs.Event { return xs[:len(xs)-1] }},
		{"generation_not_reset", func(xs []logs.Event) []logs.Event { xs[7].Record.Fields["engine_run"] = "3"; return xs }},
		{"wide_generation", func(xs []logs.Event) []logs.Event {
			xs[3].Record.Fields["engine_run"] = "18446744073709551615"
			return xs
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, origin := engineHistoryFixture(t, "0x0000000000000000000000000000000000000001")
			r, err := FitRuntime(rows[0].Node, "native", tc.change(rows), origin)
			if err != nil || r.EngineHistory == nil || r.EngineHistory.Status != "partial" || len(r.EngineHistory.Issues) == 0 || r.ReplayWAL != nil {
				t.Fatal("unproved engine history accepted", r, err)
			}
			for _, e := range r.Events {
				if e.Action == sim.ActionEngineStop || e.Action == sim.ActionEngineStart {
					t.Fatal("partial evidence scheduled an engine action", e)
				}
			}
		})
	}
}

func TestRecordedEngineControlsReachTheRealSimulatorRunner(t *testing.T) {
	nodes, links := completeFixture()
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, []time.Duration{0}, []time.Duration{0}, sim.Stop{Height: 3, Duration: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	runtimes := []Runtime{}
	for i, n := range nodes {
		r := Runtime{Node: n.Address.Hex(), Starts: 1, SignFloorState: "none"}
		if i == 0 {
			rows, origin := engineHistoryFixture(t, strings.ToLower(n.Address.Hex()))
			r, err = FitRuntime(rows[0].Node, "native", rows, origin)
			if err != nil {
				t.Fatal(err)
			}
		}
		runtimes = append(runtimes, r)
	}
	prepared, err := ApplyRuntime(sc, nodes, runtimes)
	if err != nil || len(prepared.Schedule) != 7 {
		t.Fatal(prepared.Schedule, err)
	}
	result, err := sim.Run(context.Background(), prepared, sim.Output{})
	if err != nil || len(result.Violations) != 0 {
		t.Fatal(err, result.Violations)
	}
	starts, engines := 0, 0
	for _, data := range result.Events {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var row struct {
				Node string     `json:"node"`
				Kind event.Kind `json:"kind"`
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatal(err)
			}
			if row.Node == strings.ToLower(prepared.Validators[0].Address().Hex()) {
				if row.Kind == event.NodeStart {
					starts++
				}
				if row.Kind == event.EngineStart {
					engines++
				}
			}
		}
	}
	if starts != 2 || engines != 4 {
		t.Fatal("engine history became full node restarts", starts, engines)
	}
	runtimes[0].EngineHistory = nil
	if _, err := ApplyRuntime(sc, nodes, runtimes); err == nil {
		t.Fatal("unverified engine action scheduled")
	}
}
