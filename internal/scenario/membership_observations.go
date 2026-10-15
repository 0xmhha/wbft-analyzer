package scenario

import (
	"errors"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

// These are observations of Result.Chain, the simulator's longest chain.
// They do not assert that each node has imported or agrees on that chain.
type SeedMembershipObservations struct {
	Source             string                `json:"source"`
	Scope              string                `json:"scope"`
	Epochs             []SeedMembershipEpoch `json:"epochs"`
	UnobservedRequests []MembershipEpoch     `json:"unobserved_requests"`
}

type SeedMembershipEpoch struct {
	Block             uint64                    `json:"block,string"`
	BlockHash         string                    `json:"block_hash"`
	GovernsFrom       uint64                    `json:"governs_from,string"`
	NextBlockObserved bool                      `json:"next_block_observed"`
	Candidates        []SeedMembershipCandidate `json:"candidates"`
	Validators        []SeedMembershipValidator `json:"validators"`
}

type SeedMembershipCandidate struct {
	Node      int    `json:"node"`
	Address   string `json:"simulated_address"`
	Diligence uint64 `json:"diligence,string"`
}

type SeedMembershipValidator struct {
	Node      int    `json:"node"`
	Candidate uint32 `json:"candidate_index"`
	Address   string `json:"simulated_address"`
}

func observedMembership(sc sim.Scenario, result *sim.Result, requests []MembershipEpoch) (*SeedMembershipObservations, error) {
	if result == nil {
		return nil, errors.New("simulator membership result missing")
	}
	out := &SeedMembershipObservations{Source: "official_simulator_epoch_headers/1", Scope: "longest_result_chain_not_each_node", Epochs: []SeedMembershipEpoch{}, UnobservedRequests: []MembershipEpoch{}}
	index := map[types.Address]int{}
	for i, v := range sc.Validators {
		index[v.Address()] = i
	}
	observed := map[uint64]bool{}
	for _, b := range result.Chain {
		if b == nil || b.Header == nil || !b.Header.Number.IsUint64() {
			return nil, errors.New("invalid simulator membership header")
		}
		h := b.Header.Number.Big().Uint64()
		x, err := codec.DecodeExtra(b.Header)
		if err != nil {
			return nil, err
		}
		if x.EpochInfo == nil {
			continue
		}
		info := x.EpochInfo
		if len(info.Candidates) == 0 || len(info.Validators) == 0 || len(info.Validators) != len(info.BLSPublicKeys) {
			return nil, errors.New("invalid simulator epoch selection")
		}
		e := SeedMembershipEpoch{Block: h, BlockHash: codec.BlockHash(b.Header).Hex(), GovernsFrom: h + 1, NextBlockObserved: h+1 < uint64(len(result.Chain)), Candidates: []SeedMembershipCandidate{}, Validators: []SeedMembershipValidator{}}
		seen := map[types.Address]bool{}
		for _, candidate := range info.Candidates {
			n, ok := index[candidate.Addr]
			if !ok || seen[candidate.Addr] {
				return nil, errors.New("simulator epoch candidate outside declared node universe")
			}
			seen[candidate.Addr] = true
			e.Candidates = append(e.Candidates, SeedMembershipCandidate{Node: n, Address: candidate.Addr.Hex(), Diligence: candidate.Diligence})
		}
		selected := map[uint32]bool{}
		for i, c := range info.Validators {
			if int(c) >= len(e.Candidates) || selected[c] || len(info.BLSPublicKeys[i]) == 0 {
				return nil, errors.New("invalid simulator validator index")
			}
			selected[c] = true
			candidate := e.Candidates[c]
			e.Validators = append(e.Validators, SeedMembershipValidator{Node: candidate.Node, Candidate: c, Address: candidate.Address})
		}
		out.Epochs = append(out.Epochs, e)
		observed[h] = true
	}
	for _, request := range requests {
		if !observed[request.Block] {
			out.UnobservedRequests = append(out.UnobservedRequests, MembershipEpoch{Block: request.Block, Candidates: append([]int{}, request.Candidates...)})
		}
	}
	return out, nil
}
