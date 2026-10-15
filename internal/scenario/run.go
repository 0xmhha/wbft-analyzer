package scenario

import (
	"context"
	"errors"
	"sort"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
)

type Height struct {
	Number        uint64 `json:"number,string"`
	Round         uint64 `json:"round,string"`
	Time          uint64 `json:"time,string"`
	PeriodSeconds uint64 `json:"period_seconds,string"`
}

type SeedResult struct {
	Execution    *SeedExecution `json:"execution,omitempty"`
	Seed         int64          `json:"seed"`
	Status       string         `json:"status"`
	Heights      []Height       `json:"heights"`
	Violations   int            `json:"violations"`
	SimulationNS int64          `json:"simulation_ns"`
}

// SeedExecution retains the official simulator's outcomes without inferring
// violation kinds from counts or assigning recorded identities to test keys.
type SeedExecution struct {
	StopHeight uint64          `json:"configured_stop_height,string"`
	DurationNS int64           `json:"configured_duration_ns,string"`
	Nodes      []SeedNode      `json:"nodes"`
	Violations []SeedViolation `json:"violations"`
}

type SeedNode struct {
	Index   int    `json:"index"`
	Address string `json:"simulated_address"`
	Head    uint64 `json:"head,string"`
}

type SeedViolation struct {
	Kind   string `json:"kind"`
	Node   string `json:"simulated_node"`
	Detail string `json:"detail"`
}

func seedExecution(sc sim.Scenario, result *sim.Result) *SeedExecution {
	out := &SeedExecution{StopHeight: sc.Until.Height, DurationNS: int64(sc.Until.Duration), Nodes: []SeedNode{}, Violations: []SeedViolation{}}
	for i, head := range result.Heads {
		address := ""
		if i < len(sc.Validators) {
			address = sc.Validators[i].Address().Hex()
		}
		out.Nodes = append(out.Nodes, SeedNode{Index: i, Address: address, Head: head})
	}
	for _, v := range result.Violations {
		out.Violations = append(out.Violations, SeedViolation{Kind: v.Kind, Node: v.Node.Hex(), Detail: v.Detail})
	}
	return out
}

// RunSeeds uses the official simulator with one independent run per seed.
// It never aggregates multiple node claims as independent height samples.
func RunSeeds(ctx context.Context, sc sim.Scenario, seeds []int64, from, to uint64, emit func(SeedResult) error) error {
	if from < 1 || to < from || to-from >= 10000 || len(seeds) == 0 || len(seeds) > 128 {
		return errors.New("invalid bounded simulation run")
	}
	seen := map[int64]bool{}
	for _, seed := range seeds {
		if seen[seed] {
			return errors.New("duplicate seed")
		}
		seen[seed] = true
	}
	for _, seed := range seeds {
		if err := ctx.Err(); err != nil {
			return err
		}
		sc.Seed = seed
		result, err := sim.Run(ctx, sc, sim.Output{})
		if err != nil {
			return err
		}
		out := SeedResult{Execution: seedExecution(sc, result), Seed: seed, Status: "complete", Heights: []Height{}, Violations: len(result.Violations), SimulationNS: int64(result.SimTime)}
		for _, b := range result.Chain {
			n := b.Header.Number
			if !n.IsUint64() {
				return errors.New("simulation height exceeds index domain")
			}
			h := n.Big().Uint64()
			if h < from || h > to {
				continue
			}
			round, ok := result.Rounds[h]
			if !ok {
				out.Status = "partial"
				continue
			}
			extra, err := codec.DecodeExtra(b.Header)
			if err != nil || uint64(extra.Round) != round {
				return errors.New("simulation round summary disagrees with header")
			}
			if h >= uint64(len(result.Chain)) || b.Header.Time < result.Chain[h-1].Header.Time {
				return errors.New("simulation parent time unavailable")
			}
			out.Heights = append(out.Heights, Height{Number: h, Round: round, Time: b.Header.Time, PeriodSeconds: b.Header.Time - result.Chain[h-1].Header.Time})
		}
		sort.Slice(out.Heights, func(i, j int) bool { return out.Heights[i].Number < out.Heights[j].Number })
		if len(out.Heights) != int(to-from+1) {
			out.Status = "partial"
		}
		if out.Violations > 0 {
			out.Status = "violations"
		}
		if err := emit(out); err != nil {
			return err
		}
	}
	return nil
}
