package scenario

import (
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
)

type TimingConfiguration struct {
	RequestTimeoutMS         uint64 `json:"request_timeout_ms,string"`
	BlockPeriodSeconds       uint64 `json:"block_period_seconds,string"`
	MaxRequestTimeoutSeconds uint64 `json:"max_request_timeout_seconds,string"`
}

type NodeTimingEffect struct {
	Node   int                 `json:"node"`
	Before TimingConfiguration `json:"before"`
	After  TimingConfiguration `json:"after"`
}

// TimingEffect describes resolved configuration, separately from runtime evidence.
type TimingEffect struct {
	Source string             `json:"source"`
	Scope  string             `json:"scope"`
	Order  string             `json:"precedence"`
	Nodes  []NodeTimingEffect `json:"nodes"`
}

func resolvedTiming(base sim.Params, override *sim.TimingParams, horizon time.Duration) (TimingConfiguration, error) {
	params, err := sim.ResolveTiming(base, override, horizon)
	if err != nil || params.RequestTimeoutSeconds == 0 || params.BlockPeriodSeconds == 0 {
		return TimingConfiguration{}, errNetworkChange
	}
	out := TimingConfiguration{RequestTimeoutMS: params.RequestTimeoutSeconds * 1000, BlockPeriodSeconds: params.BlockPeriodSeconds}
	if params.MaxRequestTimeoutSeconds != nil {
		out.MaxRequestTimeoutSeconds = *params.MaxRequestTimeoutSeconds
	}
	return out, nil
}

func TimingChangeEvidence(sc sim.Scenario, change NetworkChange) (*TimingEffect, error) {
	if change.Kind != "set_timing" {
		return nil, nil
	}
	changed, _, err := ApplyNetworkChange(sc, change)
	if err != nil {
		return nil, err
	}
	out := &TimingEffect{Source: "resolved_simulator_configuration/1", Scope: "whole_registered_run_all_incarnations", Order: "global_then_node_explicit_fields", Nodes: []NodeTimingEffect{}}
	for i := range sc.Nodes {
		before, err := resolvedTiming(sc.Params, sc.Nodes[i].Timing, sc.Until.Duration)
		if err != nil {
			return nil, err
		}
		after, err := resolvedTiming(changed.Params, changed.Nodes[i].Timing, changed.Until.Duration)
		if err != nil {
			return nil, err
		}
		out.Nodes = append(out.Nodes, NodeTimingEffect{Node: i, Before: before, After: after})
	}
	return out, nil
}
