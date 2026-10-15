package scenario

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
)

// ApplyRuntime binds recorded lifecycle actions to fitted validator indices.
// At equal times the fitted model uses caller source order; it does not claim
// to reconstruct an unrecorded global inter-node execution order.
func ApplyRuntime(sc sim.Scenario, nodes []Node, runtimes []Runtime) (sim.Scenario, error) {
	if len(nodes) != len(sc.Validators) || len(runtimes) != len(nodes) || len(sc.Nodes) != len(nodes) {
		return sc, errors.New("incomplete node lifecycle scope")
	}
	byNode := map[string]int{}
	for i, n := range nodes {
		byNode[strings.ToLower(n.Address.Hex())] = i
	}
	sc.Nodes = append([]sim.NodeSpec(nil), sc.Nodes...)
	schedule := append([]sim.NodeEvent(nil), sc.Schedule...)
	seen := map[string]bool{}
	for _, r := range runtimes {
		i, ok := byNode[strings.ToLower(r.Node)]
		if !ok || seen[strings.ToLower(r.Node)] || r.Starts == 0 || r.StartNS < 0 || time.Duration(r.StartNS) >= sc.Until.Duration || r.SignFloorState != "none" || r.SignFloor != nil {
			return sc, errors.New("unproved node lifecycle")
		}
		seen[strings.ToLower(r.Node)] = true

		sc.Nodes[i].StartAfter = time.Duration(r.StartNS)
		for _, e := range r.Events {
			engine := e.Action == sim.ActionEngineStart || e.Action == sim.ActionEngineStop
			if e.AtNS < r.StartNS || time.Duration(e.AtNS) > sc.Until.Duration || e.Line <= 0 || e.Run == "" || e.Action != "stop" && e.Action != "restart" && !engine || engine && !verifiedEngineAction(r, e) {
				return sc, errors.New("invalid recorded lifecycle event")
			}
			schedule = append(schedule, sim.NodeEvent{At: time.Duration(e.AtNS), Node: sc.Validators[i].Address(), Action: e.Action})
		}
	}
	sort.SliceStable(schedule, func(i, j int) bool { return schedule[i].At < schedule[j].At })
	sc.Schedule = schedule
	return sc, nil
}
