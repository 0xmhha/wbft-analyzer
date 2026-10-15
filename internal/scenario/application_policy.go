package scenario

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/events"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/event"
)

// ApplicationPolicy retains a declaration at its exact startup source. It does
// not infer a physical executor policy from successful timing samples.
type ApplicationPolicy struct {
	Node           string                     `json:"node"`
	Input          string                     `json:"input"`
	Run            string                     `json:"run"`
	Line           int64                      `json:"line"`
	Status         string                     `json:"status"`
	BuildQueue     string                     `json:"build_queue"`
	DoneResult     string                     `json:"done_result"`
	AssemblyReturn string                     `json:"assembly_return"`
	Selection      string                     `json:"selection"`
	Sealing        *events.SealingDeclaration `json:"sealing,omitempty"`
}

func FitApplicationPolicies(node, input string, xs []logs.Event) ([]ApplicationPolicy, error) {
	out := []ApplicationPolicy{}
	for _, x := range xs {
		if x.Node != node || x.Input != input || x.Profile != logs.EventProfile {
			return nil, errors.New("application policy source identity mismatch")
		}
		if x.Record.Kind != event.NodeStart {
			continue
		}
		if x.Line < 1 || x.Run == "" || len(out) >= 256 {
			return nil, errors.New("invalid application policy startup scope")
		}
		p := ApplicationPolicy{Node: node, Input: input, Run: x.Run, Line: x.Line, Status: "unavailable"}
		p.BuildQueue, _ = x.Record.Fields["application_build_queue"].(string)
		p.DoneResult, _ = x.Record.Fields["application_done_result"].(string)
		p.AssemblyReturn, _ = x.Record.Fields["application_assembly_return"].(string)
		p.Selection, _ = x.Record.Fields["application_selection"].(string)
		if p.BuildQueue == sim.BuildQueueSealing {
			p.Sealing, _ = events.SealingDeclarationFromMetadata(x.Record.Fields)
		}
		if supportedApplicationPolicy(p) {
			p.Status = "declared_simulator"
		}
		out = append(out, p)
	}
	return out, nil
}

func supportedApplicationPolicy(p ApplicationPolicy) bool {
	if p.BuildQueue == sim.BuildQueueSealing {
		return p.DoneResult == "" && p.AssemblyReturn == "sampled_empty_body" && p.Selection == "actors_to_idle_then_deadline_callbacks_seeded" && p.Sealing.Valid()
	}
	return p.Sealing == nil && p.BuildQueue == "serial-latest" && (p.DoneResult == "failed" || p.DoneResult == "submitted") && p.AssemblyReturn == "sampled" && p.Selection == "callbacks_then_done_then_pending"
}

func nodeApplicationPolicy(node string, policies []ApplicationPolicy) (ApplicationPolicy, bool) {
	var found ApplicationPolicy
	seen := map[string]bool{}
	for _, p := range policies {
		if !strings.EqualFold(p.Node, node) {
			continue
		}
		if p.Status != "declared_simulator" || !supportedApplicationPolicy(p) || p.Input == "" || p.Run == "" || p.Line < 1 || seen[p.Run] {
			return ApplicationPolicy{}, false
		}
		seen[p.Run] = true
		if found.Status != "" && (found.BuildQueue != p.BuildQueue || found.DoneResult != p.DoneResult || found.AssemblyReturn != p.AssemblyReturn || found.Selection != p.Selection || !reflect.DeepEqual(found.Sealing, p.Sealing)) {
			return ApplicationPolicy{}, false
		}
		found = p
	}
	return found, found.Status != ""
}

// ApplyApplicationPolicies never fills missing declarations with simulator
// defaults, nor assigns one node's application policy to another node.
func ApplyApplicationPolicies(sc sim.Scenario, nodes []Node, policies []ApplicationPolicy) (sim.Scenario, error) {
	if len(nodes) != len(sc.Nodes) || len(nodes) < 2 {
		return sc, errors.New("invalid application policy node scope")
	}
	specs := append([]sim.NodeSpec(nil), sc.Nodes...)
	known := map[string]bool{}
	for i, n := range nodes {
		addr := strings.ToLower(n.Address.Hex())
		p, ok := nodeApplicationPolicy(addr, policies)
		if known[addr] || !ok {
			return sc, errors.New("application policy unavailable or inconsistent")
		}
		known[addr] = true
		specs[i].BuildQueuePolicy = p.BuildQueue
		specs[i].BuildDoneResult = p.DoneResult
		specs[i].Sealing = nil
		if p.Sealing != nil {
			call, err := declaredDurations(p.Sealing.CallReturnDelayNS, sc.Until.Duration)
			if err != nil {
				return sc, err
			}
			post, err := declaredDurations(p.Sealing.PostDelayNS, sc.Until.Duration)
			if err != nil {
				return sc, err
			}
			build, err := declaredDurations(p.Sealing.AssemblyDelayNS, sc.Until.Duration)
			if err != nil {
				return sc, err
			}
			imports, err := declaredDurations(p.Sealing.ImportDelayNS, sc.Until.Duration)
			if err != nil {
				return sc, err
			}
			specs[i].Sealing = &sim.SealingProfile{Selection: sim.SealingSeeded, ResultCapacity: p.Sealing.ResultCapacity, CallDelay: call, PostDelay: post}
			specs[i].BuildDelay, specs[i].ImportDelay = build, imports
		}
	}
	for _, p := range policies {
		if !known[strings.ToLower(p.Node)] {
			return sc, errors.New("application policy outside node scope")
		}
	}
	sc.Nodes = specs
	return sc, nil
}

func declaredDurations(values []string, until time.Duration) ([]time.Duration, error) {
	out := make([]time.Duration, len(values))
	if until <= 0 {
		return nil, errors.New("application policy requires an explicit run duration")
	}
	for i, s := range values {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 || time.Duration(n) > until {
			return nil, errors.New("application policy delay outside run duration")
		}
		out[i] = time.Duration(n)
	}
	return out, nil
}
