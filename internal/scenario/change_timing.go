package scenario

import (
	"bytes"
	"cmp"
	"encoding/json"
	"slices"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
)

// TimingValues uses decimal strings so API clients never round integer seconds.
// Missing fields inherit; an explicit zero maximum removes the timeout cap.
type TimingValues struct {
	RequestTimeoutSeconds    *uint64 `json:"request_timeout_seconds,string,omitempty" nullable:"false"`
	BlockPeriodSeconds       *uint64 `json:"block_period_seconds,string,omitempty" nullable:"false"`
	MaxRequestTimeoutSeconds *uint64 `json:"max_request_timeout_seconds,string,omitempty" nullable:"false"`
}

type NodeTimingChange struct {
	Node   *int         `json:"node" nullable:"false"`
	Values TimingValues `json:"values"`
}

type TimingChange struct {
	Global *TimingValues      `json:"global,omitempty" nullable:"false"`
	Nodes  []NodeTimingChange `json:"nodes,omitempty"`
}

// Exact field names and explicit non-null values are required at every level.
func decodeTimingObject(raw []byte, target any, allowed map[string]bool, required ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return errNetworkChange
	}
	for name, value := range fields {
		if !allowed[name] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errNetworkChange
		}
	}
	for _, name := range required {
		if _, found := fields[name]; !found {
			return errNetworkChange
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func (v *TimingValues) UnmarshalJSON(raw []byte) error {
	type wire TimingValues
	var decoded wire
	if err := decodeTimingObject(raw, &decoded, map[string]bool{"request_timeout_seconds": true, "block_period_seconds": true, "max_request_timeout_seconds": true}); err != nil {
		return err
	}
	if decoded.RequestTimeoutSeconds == nil && decoded.BlockPeriodSeconds == nil && decoded.MaxRequestTimeoutSeconds == nil {
		return errNetworkChange
	}
	*v = TimingValues(decoded)
	return nil
}

func (v *NodeTimingChange) UnmarshalJSON(raw []byte) error {
	type wire NodeTimingChange
	var decoded wire
	if err := decodeTimingObject(raw, &decoded, map[string]bool{"node": true, "values": true}, "node", "values"); err != nil {
		return err
	}
	*v = NodeTimingChange(decoded)
	return nil
}

func (v *TimingChange) UnmarshalJSON(raw []byte) error {
	type wire TimingChange
	var decoded wire
	if err := decodeTimingObject(raw, &decoded, map[string]bool{"global": true, "nodes": true}); err != nil {
		return err
	}
	*v = TimingChange(decoded)
	return nil
}

func timingPointer(v *uint64) *uint64 {
	if v == nil {
		return nil
	}
	copy := *v
	return &copy
}

func (v TimingValues) params() *sim.TimingParams {
	return &sim.TimingParams{RequestTimeoutSeconds: timingPointer(v.RequestTimeoutSeconds), BlockPeriodSeconds: timingPointer(v.BlockPeriodSeconds), MaxRequestTimeoutSeconds: timingPointer(v.MaxRequestTimeoutSeconds)}
}

func cloneTimingValues(v TimingValues, horizon time.Duration) (TimingValues, error) {
	if v.RequestTimeoutSeconds == nil && v.BlockPeriodSeconds == nil && v.MaxRequestTimeoutSeconds == nil {
		return TimingValues{}, errNetworkChange
	}
	p := v.params()
	if _, err := sim.ResolveTiming(sim.Params{}, p, horizon); err != nil {
		return TimingValues{}, errNetworkChange
	}
	return TimingValues{RequestTimeoutSeconds: p.RequestTimeoutSeconds, BlockPeriodSeconds: p.BlockPeriodSeconds, MaxRequestTimeoutSeconds: p.MaxRequestTimeoutSeconds}, nil
}

func normalizeTimingChange(c NetworkChange) (NetworkChange, error) {
	if c.FromNS != 0 || c.Timing == nil || c.Node != nil || c.Edges != nil || c.DelayNS != nil || c.Scale != nil || c.Lifecycle != nil || c.SchedulePolicy != "" || len(c.Timing.Nodes) > maxChangeNodes || c.Timing.Nodes != nil && len(c.Timing.Nodes) == 0 || c.Timing.Global == nil && len(c.Timing.Nodes) == 0 {
		return NetworkChange{}, errNetworkChange
	}
	out := &TimingChange{}
	if c.Timing.Global != nil {
		value, err := cloneTimingValues(*c.Timing.Global, time.Duration(c.ToNS))
		if err != nil {
			return NetworkChange{}, err
		}
		out.Global = &value
	}
	if len(c.Timing.Nodes) > 0 {
		out.Nodes = make([]NodeTimingChange, len(c.Timing.Nodes))
	}
	for i, node := range c.Timing.Nodes {
		if node.Node == nil || *node.Node < 0 || *node.Node >= maxChangeNodes {
			return NetworkChange{}, errNetworkChange
		}
		value, err := cloneTimingValues(node.Values, time.Duration(c.ToNS))
		if err != nil {
			return NetworkChange{}, err
		}
		out.Nodes[i] = NodeTimingChange{Node: copyNode(node.Node), Values: value}
	}
	slices.SortFunc(out.Nodes, func(a, b NodeTimingChange) int { return cmp.Compare(*a.Node, *b.Node) })
	for i := 1; i < len(out.Nodes); i++ {
		if *out.Nodes[i-1].Node == *out.Nodes[i].Node {
			return NetworkChange{}, errNetworkChange
		}
	}
	c.Timing = out
	return c, nil
}

// overlayTiming only changes explicitly requested fields. Global requests
// apply to every node; per-node requests then take precedence over them.
func overlayTiming(old *sim.TimingParams, update *TimingValues) *sim.TimingParams {
	if old == nil && update == nil {
		return nil
	}
	out := &sim.TimingParams{}
	if old != nil {
		out.RequestTimeoutSeconds = timingPointer(old.RequestTimeoutSeconds)
		out.BlockPeriodSeconds = timingPointer(old.BlockPeriodSeconds)
		out.MaxRequestTimeoutSeconds = timingPointer(old.MaxRequestTimeoutSeconds)
	}
	if update != nil {
		if update.RequestTimeoutSeconds != nil {
			out.RequestTimeoutSeconds = timingPointer(update.RequestTimeoutSeconds)
		}
		if update.BlockPeriodSeconds != nil {
			out.BlockPeriodSeconds = timingPointer(update.BlockPeriodSeconds)
		}
		if update.MaxRequestTimeoutSeconds != nil {
			out.MaxRequestTimeoutSeconds = timingPointer(update.MaxRequestTimeoutSeconds)
		}
	}
	return out
}

func applyTimingChange(sc sim.Scenario, c NetworkChange) (sim.Scenario, string, error) {
	if len(sc.Nodes) != len(sc.Validators) {
		return sc, "", errNetworkChange
	}
	var global *sim.TimingParams
	if c.Timing.Global != nil {
		global = c.Timing.Global.params()
	}
	params, err := sim.ResolveTiming(sc.Params, global, sc.Until.Duration)
	if err != nil {
		return sc, "", err
	}
	nodes := slices.Clone(sc.Nodes)
	for i := range nodes {
		nodes[i].Timing = overlayTiming(nodes[i].Timing, c.Timing.Global)
	}
	for _, update := range c.Timing.Nodes {
		nodes[*update.Node].Timing = overlayTiming(nodes[*update.Node].Timing, &update.Values)
	}
	for _, node := range nodes {
		if _, err := sim.ResolveTiming(params, node.Timing, sc.Until.Duration); err != nil {
			return sc, "", err
		}
	}
	sc.Params, sc.Nodes = params, nodes
	_, hash, err := c.Canonical()
	return sc, hash, err
}
