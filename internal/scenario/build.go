package scenario

import (
	"errors"
	"math"
	"strings"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

type Node struct {
	ProfileEvidence string
	Address         types.Address
	Improvements    uint64
	BacklogLimit    int
	Profile         string
	ReplayWAL       bool
	RuntimeInput    string
	RuntimeLine     int64
	RuntimeEvidence string
	SignFloor       *string
}

// Build requires every directed link model; missing links never use the
// simulator's synthetic default latency or zero-loss assumption.
func Build(nodes []Node, links []Link, params sim.Params, build, imports []time.Duration, until sim.Stop) (sim.Scenario, error) {
	return buildScenario(nodes, links, params, build, imports, until, DeclaredRuntimeModel)
}

func buildScenario(nodes []Node, links []Link, params sim.Params, build, imports []time.Duration, until sim.Stop, model string) (sim.Scenario, error) {
	out := sim.Scenario{Params: params, Until: until, Links: []sim.Link{}, Nodes: []sim.NodeSpec{}}
	if params.RequestTimeoutSeconds == 0 || params.BlockPeriodSeconds == 0 || params.EpochLength == 0 || len(build) == 0 || len(imports) == 0 || until.Height == 0 || until.Height > 10000 || until.Duration <= 0 || until.Duration > 24*time.Hour {
		return out, errors.New("incomplete bounded scenario configuration")
	}
	addresses := make([]types.Address, len(nodes))
	index := map[string]int{}
	for i, n := range nodes {
		modeled := model == EmpiricalCoreModel && n.RuntimeEvidence == "modeled_core_substitution" && n.ProfileEvidence == "modeled_core_substitution" && n.Profile == "compat" && n.Improvements == 0 && n.BacklogLimit == 0 && !n.ReplayWAL
		if n.Profile != "compat" && n.Profile != "improved" || n.BacklogLimit < 0 || n.RuntimeEvidence != "verified" && !modeled || n.SignFloor != nil {
			return out, errors.New("invalid node configuration")
		}
		addresses[i] = n.Address
		index[strings.ToLower(n.Address.Hex())] = i
		out.Nodes = append(out.Nodes, sim.NodeSpec{Options: consensus.Options{Improvements: consensus.ImprovementSet(n.Improvements), BacklogLimit: n.BacklogLimit}, Profile: n.Profile, ReplayWAL: n.ReplayWAL})
	}
	keys, err := TestValidators(addresses)
	if err != nil {
		return out, err
	}
	out.Validators = keys
	if len(links) != len(nodes)*(len(nodes)-1) {
		return out, errors.New("incomplete directed links")
	}
	seen := map[[2]int]bool{}
	for _, l := range links {
		a, okA := index[strings.ToLower(l.Sender)]
		b, okB := index[strings.ToLower(l.Receiver)]
		if !okA || !okB || a == b || seen[[2]int{a, b}] || l.Status != "complete" || l.Loss == nil || *l.Loss < 0 || *l.Loss >= 1 || math.IsNaN(*l.Loss) || len(l.Delays) == 0 {
			return out, errors.New("unproved directed link model")
		}
		seen[[2]int{a, b}] = true
		delays := []time.Duration{}
		for _, d := range l.Delays {
			if d.Lower < 0 || d.Upper < d.Lower || d.Nanoseconds < d.Lower || d.Nanoseconds > d.Upper {
				return out, errors.New("invalid delay model")
			}
			delays = append(delays, time.Duration(d.Lower))
			if d.Upper != d.Lower {
				delays = append(delays, time.Duration(d.Upper))
			}
		}
		out.Links = append(out.Links, sim.Link{From: keys[a].Address(), To: keys[b].Address(), Delay: delays, Loss: *l.Loss})
	}
	for _, samples := range [][]time.Duration{build, imports} {
		for _, d := range samples {
			if d < 0 || d > time.Hour {
				return out, errors.New("invalid application delay")
			}
		}
	}
	out.App = sim.AppModel{BuildDelay: append([]time.Duration(nil), build...), ImportDelay: append([]time.Duration(nil), imports...)}
	return out, nil
}
