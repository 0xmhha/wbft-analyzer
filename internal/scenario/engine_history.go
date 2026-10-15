package scenario

import (
	"strconv"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/event"
)

type EngineHistory struct {
	Status    string               `json:"status"`
	Instances []EngineInstance     `json:"instances"`
	Actions   []RuntimeEvent       `json:"actions"`
	Issues    []EngineHistoryIssue `json:"issues"`
}

type EngineInstance struct {
	Run       string `json:"run"`
	Engine    string `json:"engine_run"`
	StartNS   int64  `json:"start_ns"`
	StopNS    *int64 `json:"stop_ns"`
	StartLine int64  `json:"start_line"`
	StopLine  int64  `json:"stop_line"`
	Initial   bool   `json:"initial"`
	Terminal  bool   `json:"node_shutdown"`
}

type EngineHistoryIssue struct {
	Code string `json:"code"`
	Run  string `json:"run"`
	Line int64  `json:"line"`
}

// inspectEngineHistory requires explicit per-writer generations and closure.
// Unknown or contradictory candidates remain visible; clock proximity never
// joins one instance to another. Node teardown is not an engine-only pause.
func inspectEngineHistory(xs []logs.Event, origin time.Time) EngineHistory {
	out := EngineHistory{Status: "partial", Instances: []EngineInstance{}, Actions: []RuntimeEvent{}, Issues: []EngineHistoryIssue{}}
	count := 0
	for _, x := range xs {
		if x.Record.Kind == event.EngineStart {
			count++
		}
	}
	if count > 4096 {
		out.Issues = append(out.Issues, EngineHistoryIssue{Code: "engine_history_exceeds_bound"})
		return out
	}
	issue := func(code string, x logs.Event) {
		out.Issues = append(out.Issues, EngineHistoryIssue{Code: code, Run: x.Run, Line: x.Line})
	}
	writer := ""
	live, started := false, false
	active := -1
	var generation uint64
	seen := map[string]bool{}
	previous := origin
	last := logs.Event{}
	for _, x := range xs {
		kind := x.Record.Kind
		if kind != event.NodeStart && kind != event.NodeStop && kind != event.EngineStart && kind != event.EngineStop {
			continue
		}
		last = x
		at, err := time.Parse(time.RFC3339Nano, x.Wall)
		if err != nil || at.Before(previous) || at.Before(origin) || at.After(origin.Add(24*time.Hour)) || x.Line < 1 || x.Run == "" {
			issue("engine_history_clock_or_source_unavailable", x)
			continue
		}
		previous = at
		engine, _ := x.Record.Fields["engine_run"].(string)
		switch kind {
		case event.NodeStart:
			if live || active >= 0 || seen[x.Run] {
				issue("node_writer_history_ambiguous", x)
			}
			writer, live, started, active, generation = x.Run, true, false, -1, 0
			seen[x.Run] = true
		case event.NodeStop:
			if !live || x.Run != writer || !started {
				issue("node_shutdown_history_unavailable", x)
			}
			live = false
		case event.EngineStart:
			g, err := strconv.ParseUint(engine, 10, 64)
			if err != nil || g == 0 || strconv.FormatUint(g, 10) != engine || generation == ^uint64(0) || g != generation+1 {
				issue("engine_generation_unavailable", x)
			}
			if !live || x.Run != writer || active >= 0 {
				issue("engine_start_history_ambiguous", x)
			}
			out.Instances = append(out.Instances, EngineInstance{Run: x.Run, Engine: engine, StartNS: int64(at.Sub(origin)), StartLine: x.Line, Initial: !started})
			active = len(out.Instances) - 1
			if started {
				out.Actions = append(out.Actions, RuntimeEvent{Action: sim.ActionEngineStart, AtNS: int64(at.Sub(origin)), Run: x.Run, Engine: engine, Line: x.Line})
			}
			started, generation = true, g
		case event.EngineStop:
			if active < 0 || x.Run != writer || engine == "" || out.Instances[active].Run != x.Run || out.Instances[active].Engine != engine {
				issue("engine_stop_history_ambiguous", x)
				continue
			}
			ns := int64(at.Sub(origin))
			out.Instances[active].StopNS, out.Instances[active].StopLine, out.Instances[active].Terminal = &ns, x.Line, !live
			active = -1
			if live {
				out.Actions = append(out.Actions, RuntimeEvent{Action: sim.ActionEngineStop, AtNS: ns, Run: x.Run, Engine: engine, Line: x.Line})
			}
		}
	}
	if len(seen) == 0 || count == 0 || live || active >= 0 {
		issue("engine_history_not_closed", last)
	}
	if len(out.Issues) == 0 {
		out.Status = "complete"
	}
	return out
}

func verifiedEngineAction(r Runtime, e RuntimeEvent) bool {
	if r.EngineHistory == nil || r.EngineHistory.Status != "complete" {
		return false
	}
	for _, observed := range r.EngineHistory.Actions {
		if e == observed {
			return true
		}
	}
	return false
}
