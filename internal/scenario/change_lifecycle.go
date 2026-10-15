package scenario

import (
	"bytes"
	"cmp"
	"encoding/json"
	"slices"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

const maxLifecycleCommands = 4096

type LifecycleCommand struct {
	Node   *int   `json:"node" nullable:"false"`
	AtNS   *int64 `json:"at_ns" nullable:"false"`
	Action string `json:"action" enum:"stop,restart"`
}

func (c *LifecycleCommand) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if len(fields) != 3 {
		return errNetworkChange
	}
	for _, key := range []string{"node", "at_ns", "action"} {
		value, found := fields[key]
		if !found || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errNetworkChange
		}
	}
	type wire LifecycleCommand
	var decoded wire
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*c = LifecycleCommand(decoded)
	return nil
}

// LifecycleRecord describes a recorded command, including engine-only actions.
type LifecycleRecord struct {
	Node   int    `json:"node"`
	AtNS   int64  `json:"at_ns"`
	Action string `json:"action"`
}

type LifecycleEffect struct {
	Removed                []LifecycleRecord `json:"removed_recorded_commands"`
	Retained               int               `json:"retained_recorded_commands"`
	Order                  string            `json:"equal_time_order"`
	InitialStartsPreserved bool              `json:"initial_starts_preserved"`
}

// LifecycleScope snapshots public node indices and times, never simulator keys.
type LifecycleScope struct {
	starts   []int64
	recorded []LifecycleRecord
	duration time.Duration
}

func normalizeLifecycle(c NetworkChange) (NetworkChange, error) {
	if c.Node != nil || c.Edges != nil || c.DelayNS != nil || c.Scale != nil || len(c.Lifecycle) == 0 || len(c.Lifecycle) > maxLifecycleCommands || c.SchedulePolicy != "merge" && c.SchedulePolicy != "replace_window" {
		return NetworkChange{}, errNetworkChange
	}
	commands := make([]LifecycleCommand, len(c.Lifecycle))
	for i, command := range c.Lifecycle {
		if command.Node == nil || *command.Node < 0 || *command.Node >= maxChangeNodes || command.AtNS == nil || *command.AtNS < c.FromNS || *command.AtNS > c.ToNS || command.Action != sim.ActionStop && command.Action != sim.ActionRestart {
			return NetworkChange{}, errNetworkChange
		}
		at := *command.AtNS
		commands[i] = LifecycleCommand{Node: copyNode(command.Node), AtNS: &at, Action: command.Action}
	}
	slices.SortFunc(commands, func(a, b LifecycleCommand) int {
		if order := cmp.Compare(*a.AtNS, *b.AtNS); order != 0 {
			return order
		}
		return cmp.Compare(*a.Node, *b.Node)
	})
	for i := 1; i < len(commands); i++ {
		if *commands[i-1].AtNS == *commands[i].AtNS && *commands[i-1].Node == *commands[i].Node {
			return NetworkChange{}, errNetworkChange
		}
	}
	c.Lifecycle = commands
	return c, nil
}

func NodeLifecycleBounds(sc sim.Scenario) (LifecycleScope, error) {
	out := LifecycleScope{duration: sc.Until.Duration, starts: []int64{}, recorded: []LifecycleRecord{}}
	if len(sc.Nodes) != len(sc.Validators) || len(sc.Nodes) < 2 || len(sc.Nodes) > maxChangeNodes || sc.Until.Duration <= 0 {
		return out, errNetworkChange
	}
	indices := map[types.Address]int{}
	for i, validator := range sc.Validators {
		if _, exists := indices[validator.Address()]; exists {
			return out, errNetworkChange
		}
		indices[validator.Address()] = i
		start := sc.Nodes[i].StartAfter
		if start < 0 || start >= sc.Until.Duration {
			return out, errNetworkChange
		}
		out.starts = append(out.starts, int64(start))
	}
	for _, event := range sc.Schedule {
		node, found := indices[event.Node]
		if !found || int64(event.At) < out.starts[node] || event.At > sc.Until.Duration {
			return out, errNetworkChange
		}
		switch event.Action {
		case sim.ActionStop, sim.ActionRestart, sim.ActionEngineStop, sim.ActionEngineStart:
		default:
			return out, errNetworkChange
		}
		out.recorded = append(out.recorded, LifecycleRecord{Node: node, AtNS: int64(event.At), Action: event.Action})
	}
	return out, nil
}

type plannedLifecycle struct {
	LifecycleRecord
	intervention bool
}

func planNodeLifecycle(scope LifecycleScope, c NetworkChange) ([]plannedLifecycle, *LifecycleEffect, error) {
	if err := c.ValidateFor(len(scope.starts), scope.duration); err != nil {
		return nil, nil, err
	}
	selected := map[int]bool{}
	for _, command := range c.Lifecycle {
		if *command.AtNS < scope.starts[*command.Node] {
			return nil, nil, errNetworkChange
		}
		selected[*command.Node] = true
	}
	out := []plannedLifecycle{}
	effect := &LifecycleEffect{Removed: []LifecycleRecord{}, InitialStartsPreserved: true, Order: "recorded_first_then_intervention"}
	for _, event := range scope.recorded {
		if c.SchedulePolicy == "replace_window" && selected[event.Node] && event.AtNS >= c.FromNS && event.AtNS <= c.ToNS {
			effect.Removed = append(effect.Removed, event)
			continue
		}
		out = append(out, plannedLifecycle{LifecycleRecord: event})
		effect.Retained++
	}
	for _, command := range c.Lifecycle {
		out = append(out, plannedLifecycle{LifecycleRecord: LifecycleRecord{Node: *command.Node, AtNS: *command.AtNS, Action: command.Action}, intervention: true})
	}
	// Stable sorting keeps original source order, followed by canonical command
	// order at equal times. This is an explicit model policy, not a physical claim.
	slices.SortStableFunc(out, func(a, b plannedLifecycle) int { return cmp.Compare(a.AtNS, b.AtNS) })
	alive := make([]bool, len(scope.starts))
	for i := range alive {
		alive[i] = true
	}
	for _, event := range out {
		switch event.Action {
		case sim.ActionStop:
			if event.intervention && !alive[event.Node] {
				return nil, nil, errNetworkChange
			}
			alive[event.Node] = false
		case sim.ActionRestart:
			if event.intervention && alive[event.Node] {
				return nil, nil, errNetworkChange
			}
			alive[event.Node] = true
		}
	}
	return out, effect, nil
}

func (c NetworkChange) ValidateLifecycleBounds(scope LifecycleScope) error {
	normalized, err := c.Normalized()
	if err != nil {
		return err
	}
	if normalized.Kind != "node_lifecycle" {
		return nil
	}
	_, _, err = planNodeLifecycle(scope, normalized)
	return err
}

func NodeLifecycleEvidence(sc sim.Scenario, c NetworkChange) (*LifecycleEffect, error) {
	if c.Kind != "node_lifecycle" {
		return nil, nil
	}
	scope, err := NodeLifecycleBounds(sc)
	if err != nil {
		return nil, err
	}
	normalized, err := c.Normalized()
	if err != nil {
		return nil, err
	}
	_, effect, err := planNodeLifecycle(scope, normalized)
	return effect, err
}

func applyNodeLifecycle(sc sim.Scenario, c NetworkChange) (sim.Scenario, string, error) {
	scope, err := NodeLifecycleBounds(sc)
	if err != nil {
		return sc, "", err
	}
	plan, _, err := planNodeLifecycle(scope, c)
	if err != nil {
		return sc, "", err
	}
	schedule := make([]sim.NodeEvent, len(plan))
	for i, event := range plan {
		schedule[i] = sim.NodeEvent{At: time.Duration(event.AtNS), Node: sc.Validators[event.Node].Address(), Action: event.Action}
	}
	sc.Schedule = schedule
	_, hash, err := c.Canonical()
	return sc, hash, err
}
