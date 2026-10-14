package scenario

import (
	"errors"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

type ChainFacts struct {
	GenesisCount int
	Epochs       []RecordedEpoch
	Issues       []Issue
	Validators   []types.Address
	Params       sim.Params
	Heights      []Height
}

// InspectChain derives network observations from the canonical block chain.
// Child PrevRound is the network-wide decision record; the final block has
// no child and is deliberately outside the comparison range.
func InspectChain(blocks []*types.Block, cfg *types.Config, from, to uint64) (ChainFacts, error) {
	out := ChainFacts{Validators: []types.Address{}, Heights: []Height{}}
	if cfg == nil || from < 1 || to < from || to-from >= 10000 || len(blocks) < 3 || to >= uint64(len(blocks)-1) {
		return out, errors.New("invalid chain scenario range")
	}
	for i, b := range blocks {
		if b == nil || b.Header == nil || !b.Header.Number.IsUint64() || b.Header.Number.Big().Uint64() != uint64(i) {
			return out, errors.New("invalid canonical chain indices")
		}
		if i > 0 && b.Header.ParentHash != codec.BlockHash(blocks[i-1].Header) {
			return out, errors.New("canonical chain parent mismatch")
		}
	}
	genesis, err := codec.DecodeExtra(blocks[0].Header)
	if err != nil || genesis.EpochInfo == nil {
		return out, errors.New("genesis validator evidence unavailable")
	}
	out.Validators = genesis.EpochInfo.ValidatorAddresses()
	out.GenesisCount = len(out.Validators)
	if len(out.Validators) < 2 || len(out.Validators) > 256 {
		return out, errors.New("invalid genesis validators")
	}
	base := cfg.ConfigAt(types.HeightFromUint64(from))
	if base.ProposerPolicy == nil {
		return out, errors.New("proposer policy unavailable")
	}
	if base.RequestTimeoutMs == 0 || base.RequestTimeoutMs%1000 != 0 {
		return out, errors.New("timeout cannot be represented by simulator seconds")
	}
	capSeconds := base.MaxRequestTimeoutSeconds
	out.Params = sim.Params{RequestTimeoutSeconds: base.RequestTimeoutMs / 1000, BlockPeriodSeconds: base.BlockPeriodSeconds, EpochLength: base.EpochLength, ProposerPolicy: base.ProposerPolicy.ID, MaxRequestTimeoutSeconds: &capSeconds}
	// Simulation starts at genesis, including the warm-up before From.
	for h := uint64(0); h <= to; h++ {
		params := cfg.ConfigAt(types.HeightFromUint64(h))
		if params.ProposerPolicy == nil || params.ProposerPolicy.ID != base.ProposerPolicy.ID || params.RequestTimeoutMs != base.RequestTimeoutMs || params.BlockPeriodSeconds != base.BlockPeriodSeconds || params.EpochLength != base.EpochLength || params.MaxRequestTimeoutSeconds != base.MaxRequestTimeoutSeconds {
			return out, errors.New("scenario configuration transitions require explicit fitting")
		}
		if h < from {
			continue
		}
		child, err := codec.DecodeExtra(blocks[h+1].Header)
		if err != nil {
			return out, err
		}
		if blocks[h].Header.Time < blocks[h-1].Header.Time {
			return out, errors.New("chain time regression")
		}
		out.Heights = append(out.Heights, Height{Number: h, Round: uint64(child.PrevRound), Time: blocks[h].Header.Time, PeriodSeconds: blocks[h].Header.Time - blocks[h-1].Header.Time})
	}
	out.Validators, out.Epochs, out.Issues, err = inspectEpochs(blocks, cfg, to, out.Validators)
	if err != nil {
		return out, err
	}
	return out, nil
}
