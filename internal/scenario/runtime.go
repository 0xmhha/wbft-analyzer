package scenario

import (
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

type Runtime struct {
	EngineStopped  bool           `json:"engine_stop_observed"`
	ReplayWAL      *bool          `json:"wal_replay"`
	WALPolicies    []WALPolicy    `json:"wal_policies"`
	Node           string         `json:"node"`
	Input          string         `json:"input"`
	StartNS        int64          `json:"start_ns"`
	Starts         int            `json:"starts"`
	SignFloor      *string        `json:"sign_floor"`
	SignFloorState string         `json:"sign_floor_state"`
	Events         []RuntimeEvent `json:"events"`
}

type WALPolicy struct {
	Run       string `json:"run"`
	Engine    string `json:"engine_run"`
	Line      int64  `json:"line"`
	Enabled   *bool  `json:"enabled"`
	Available *bool  `json:"available"`
	Replayed  *bool  `json:"replayed"`
	Status    string `json:"status"`
}

type RuntimeEvent struct {
	Action string `json:"action"`
	AtNS   int64  `json:"at_ns"`
	Run    string `json:"run"`
	Line   int64  `json:"line"`
}

// FitRuntime requires native schema-checked events. NODE_START without an
// explicit null/recorded sign floor never proves that the floor is absent.
func FitRuntime(node, input string, xs []logs.Event, origin time.Time) (Runtime, error) {
	out := Runtime{Node: node, Input: input, SignFloorState: "unavailable", Events: []RuntimeEvent{}, WALPolicies: []WALPolicy{}}
	if origin.IsZero() {
		return out, errors.New("runtime origin unavailable")
	}
	running := false
	first := true
	previous := origin
	startRuns := map[string]int{}
	for _, x := range xs {
		if x.Node != node || x.Input != input || x.Profile != logs.EventProfile {
			return out, errors.New("runtime source identity mismatch")
		}
		kind := x.Record.Kind
		if kind == event.EngineStop {
			// NODE_STOP is emitted before the engine teardown during shutdown.
			// Only a stop while the node remains live needs a separate engine model.
			out.EngineStopped = out.EngineStopped || running
			continue
		}
		if kind == event.EngineStart {
			if !running {
				return out, errors.New("engine starts without recorded node start")
			}
			policy := WALPolicy{Run: x.Run, Line: x.Line}
			policy.Engine, _ = x.Record.Fields["engine_run"].(string)
			if value, ok := x.Record.Fields["wal_replay_enabled"].(bool); ok {
				policy.Enabled = &value
			}
			if value, ok := x.Record.Fields["wal_available"].(bool); ok {
				policy.Available = &value
			}
			if value, ok := x.Record.Fields["wal_replayed"].(bool); ok {
				policy.Replayed = &value
			}
			policy.Status, _ = x.Record.Fields["wal_replay_status"].(string)
			if policy.Replayed != nil && *policy.Replayed && (policy.Enabled != nil && !*policy.Enabled || policy.Available != nil && !*policy.Available) {
				return out, errors.New("inconsistent recorded replay policy")
			}
			out.WALPolicies = append(out.WALPolicies, policy)
			continue
		}
		if kind != event.NodeStart && kind != event.NodeStop {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, x.Wall)
		if err != nil || at.Before(previous) || at.Sub(origin) > 24*time.Hour {
			return out, errors.New("runtime clock outside scope")
		}
		previous = at
		if kind == event.NodeStart {
			if running {
				return out, errors.New("duplicate node start")
			}
			state, _ := x.Record.Fields["sign_floor_state"].(string)
			height, _ := x.Record.Fields["sign_floor_height"].(string)
			status, _ := x.Record.Fields["sign_floor_status"].(string)
			if state == "none" {
				if out.SignFloor != nil {
					return out, errors.New("sign floor changes require explicit model")
				}
				out.SignFloorState = "none"
			} else if height != "" && (status == "set" || status == "kept") {
				if out.SignFloorState == "none" || out.SignFloor != nil && *out.SignFloor != height {
					return out, errors.New("sign floor changes require explicit model")
				}
				out.SignFloor = &height
				out.SignFloorState = "recorded"
			} else {
				return out, errors.New("sign floor evidence unavailable")
			}
			if first {
				out.StartNS = int64(at.Sub(origin))
			}
			if !first {
				out.Events = append(out.Events, RuntimeEvent{Action: "restart", AtNS: int64(at.Sub(origin)), Run: x.Run, Line: x.Line})
			}
			first = false
			running = true
			out.Starts++
			startRuns[x.Run]++
		} else {
			if !running {
				return out, errors.New("node stop without recorded start")
			}
			running = false
			out.Events = append(out.Events, RuntimeEvent{Action: "stop", AtNS: int64(at.Sub(origin)), Run: x.Run, Line: x.Line})
		}
	}
	if first {
		return out, errors.New("node start evidence unavailable")
	}
	known := len(out.WALPolicies) == out.Starts
	policyRuns := map[string]int{}
	for _, policy := range out.WALPolicies {
		policyRuns[policy.Run]++
		if startRuns[policy.Run] != 1 || policyRuns[policy.Run] != 1 {
			known = false
		}
		if policy.Enabled == nil || policy.Available == nil || !*policy.Available || policy.Engine == "" || policy.Line < 1 || policy.Status != "complete" {
			known = false
			continue
		}
		if out.ReplayWAL != nil && *out.ReplayWAL != *policy.Enabled {
			return out, errors.New("runtime replay policy changes require explicit model")
		}
		value := *policy.Enabled
		out.ReplayWAL = &value
	}
	if !known {
		out.ReplayWAL = nil
	}
	return out, nil
}
