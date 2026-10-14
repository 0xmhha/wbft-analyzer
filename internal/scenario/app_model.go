package scenario

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
)

// ApplyAppTiming binds native measured distributions per node. Missing data
// for a node never falls back to the shared synthetic application model.
func ApplyAppTiming(sc sim.Scenario, nodes []Node, timing AppTiming) (sim.Scenario, error) {
	if len(nodes) != len(sc.Nodes) || len(nodes) < 2 || timing.Unproved > 0 {
		return sc, errors.New("incomplete measured application timing")
	}
	index := map[string]int{}
	for i, n := range nodes {
		addr := strings.ToLower(n.Address.Hex())
		if _, ok := index[addr]; ok {
			return sc, errors.New("duplicate application node")
		}
		index[addr] = i
	}
	specs := append([]sim.NodeSpec(nil), sc.Nodes...)
	for i := range specs {
		specs[i].BuildDelay = []time.Duration{}
		specs[i].ImportDelay = []time.Duration{}
	}
	for which, samples := range [][]AppSample{timing.Build, timing.Import} {
		seen := map[[4]string]bool{}
		for _, s := range samples {
			i, ok := index[strings.ToLower(s.Node)]
			if !ok || s.Input == "" || s.Run == "" || s.FromLine < 1 || s.ToLine < s.FromLine || s.Nanoseconds < 0 || time.Duration(s.Nanoseconds) > sc.Until.Duration {
				return sc, errors.New("invalid measured application sample")
			}
			key := [4]string{s.Input, s.Run, strconv.FormatInt(s.FromLine, 10), strconv.FormatInt(s.ToLine, 10)}
			if seen[key] {
				return sc, errors.New("duplicate application sample")
			}
			seen[key] = true
			if which == 0 {
				specs[i].BuildDelay = append(specs[i].BuildDelay, time.Duration(s.Nanoseconds))
			} else {
				specs[i].ImportDelay = append(specs[i].ImportDelay, time.Duration(s.Nanoseconds))
			}
		}
	}
	for _, n := range specs {
		if len(n.BuildDelay) == 0 || len(n.ImportDelay) == 0 {
			return sc, errors.New("node application observations unavailable")
		}
	}
	sc.Nodes = specs
	return sc, nil
}
