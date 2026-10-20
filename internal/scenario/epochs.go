package scenario

import (
	"bytes"
	"errors"
	"reflect"
	"slices"

	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

type RecordedEpoch struct {
	Block                uint64          `json:"block,string"`
	Candidates           []types.Address `json:"candidates"`
	Validators           []types.Address `json:"validators"`
	HeaderInputsVerified bool            `json:"header_inputs_verified"`
}

type recordedChain struct {
	blocks []*types.Block
	hashes map[types.Hash]*types.Header
}

func (c recordedChain) Head() *types.Header { return c.blocks[len(c.blocks)-1].Header }
func (c recordedChain) HeaderByNumber(n uint64) *types.Header {
	if n >= uint64(len(c.blocks)) {
		return nil
	}
	return c.blocks[n].Header
}
func (c recordedChain) HeaderByHash(h types.Hash) *types.Header { return c.hashes[h] }
func (c recordedChain) Header(h types.Hash, n uint64) *types.Header {
	x := c.HeaderByNumber(n)
	if x == nil || codec.BlockHash(x) != h {
		return nil
	}
	return x
}
func (c recordedChain) HasBlock(h types.Hash, n uint64) bool { return c.Header(h, n) != nil }

// inspectEpochs retains recorded candidate membership, not recorded selection
// as a forced simulator output. Each run must recompute diligence and order.
func inspectEpochs(blocks []*types.Block, cfg *types.Config, to uint64, genesis []types.Address) ([]types.Address, []RecordedEpoch, []Issue, error) {
	universe := append([]types.Address(nil), genesis...)
	known := map[types.Address]bool{}
	for _, a := range universe {
		if a == (types.Address{}) || known[a] {
			return nil, nil, nil, errors.New("invalid genesis validator identity")
		}
		known[a] = true
	}
	chain := recordedChain{blocks: blocks, hashes: map[types.Hash]*types.Header{}}
	for _, b := range blocks {
		chain.hashes[codec.BlockHash(b.Header)] = b.Header
	}
	plan := []RecordedEpoch{}
	issues := []Issue{}
	keys := map[types.Address][]byte{}
	for h := uint64(0); h <= to; h++ {
		x, err := codec.DecodeExtra(blocks[h].Header)
		if err != nil {
			return nil, nil, nil, err
		}
		isEpoch, err := validator.IsEpochBlock(cfg, types.HeightFromUint64(h))
		if err != nil {
			return nil, nil, nil, err
		}
		if !isEpoch {
			if x.EpochInfo != nil {
				return nil, nil, nil, errors.New("epoch evidence on a non-epoch block")
			}
			continue
		}
		info := x.EpochInfo
		if info == nil || len(info.Candidates) == 0 || len(info.Candidates) > 256 || len(info.Validators) == 0 || len(info.Validators) != len(info.BLSPublicKeys) {
			return nil, nil, nil, errors.New("invalid recorded epoch evidence")
		}
		r := RecordedEpoch{Block: h, Candidates: []types.Address{}, Validators: []types.Address{}}
		seen := map[types.Address]bool{}
		for _, c := range info.Candidates {
			if c.Addr == (types.Address{}) || seen[c.Addr] {
				return nil, nil, nil, errors.New("invalid epoch candidate identity")
			}
			seen[c.Addr] = true
			r.Candidates = append(r.Candidates, c.Addr)
			if !known[c.Addr] {
				known[c.Addr] = true
				universe = append(universe, c.Addr)
				if len(universe) > 256 {
					return nil, nil, nil, errors.New("epoch node universe exceeds bound")
				}
			}
		}
		selected := map[uint32]bool{}
		for i, index := range info.Validators {
			if int(index) >= len(info.Candidates) || selected[index] || len(info.BLSPublicKeys[i]) == 0 {
				return nil, nil, nil, errors.New("invalid recorded epoch selection")
			}
			selected[index] = true
			a := info.Candidates[index].Addr
			r.Validators = append(r.Validators, a)
			if old := keys[a]; old != nil && !bytes.Equal(old, info.BLSPublicKeys[i]) {
				issues = append(issues, Issue{Node: a.Hex(), Code: "epoch_key_rotation_model_unavailable"})
			}
			keys[a] = append([]byte(nil), info.BLSPublicKeys[i]...)
		}
		if h > 0 {
			entries := []types.CandidateEntry{}
			for _, a := range r.Candidates {
				entries = append(entries, types.CandidateEntry{Addr: a, BLSPublicKey: keys[a]})
			}
			expected, err := epoch.ComputeNextEpochInfo(chain, cfg, blocks[h].Header, entries)
			if err != nil {
				return nil, nil, nil, err
			}
			if !reflect.DeepEqual(expected, info) {
				return nil, nil, nil, errors.New("recorded epoch does not match header-derived inputs")
			}
			r.HeaderInputsVerified = true
			plan = append(plan, r)
		}
	}
	return universe, plan, issues, nil
}

func ApplyEpochs(sc sim.Scenario, original []types.Address, genesis int, plan []RecordedEpoch) (sim.Scenario, error) {
	if genesis < 2 || genesis > len(original) || len(sc.Validators) != len(original) {
		return sc, errors.New("invalid epoch simulation scope")
	}
	index := map[types.Address]int{}
	for i, a := range original {
		if _, ok := index[a]; ok {
			return sc, errors.New("duplicate epoch node")
		}
		index[a] = i
	}
	sc.Genesis = genesis
	sc.Epochs = []sim.EpochChange{}
	var previous uint64
	for _, e := range plan {
		if e.Block == 0 || e.Block <= previous || !e.HeaderInputsVerified {
			return sc, errors.New("unverified epoch schedule")
		}
		previous = e.Block
		input, err := candidateInputBlock(sc.Params, e.Block)
		if err != nil {
			return sc, err
		}
		c := sim.EpochChange{Block: input, Candidates: []int{}}
		seen := map[int]bool{}
		for _, a := range e.Candidates {
			i, ok := index[a]
			if !ok || seen[i] {
				return sc, errors.New("epoch candidate outside simulation scope")
			}
			seen[i] = true
			c.Candidates = append(c.Candidates, i)
		}
		if len(c.Candidates) == 0 {
			return sc, errors.New("empty epoch membership")
		}
		if len(sc.Epochs) > 0 && sc.Epochs[len(sc.Epochs)-1].Block == c.Block {
			if !slices.Equal(sc.Epochs[len(sc.Epochs)-1].Candidates, c.Candidates) {
				return sc, errCandidateState
			}
			continue
		}
		sc.Epochs = append(sc.Epochs, c)
	}
	return sc, nil
}
