package scenario

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

func TestChainFactsUseChildDecisionRound(t *testing.T) {
	nodes, links := completeFixture()
	delay := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, delay, delay, sim.Stop{Height: 5, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sim.Run(context.Background(), sc, sim.Output{})
	if err != nil {
		t.Fatal(err)
	}
	pol := uint64(0)
	cfg := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100, ProposerPolicy: &pol}, nil, types.GenesisInit{}, nil)
	facts, err := InspectChain(res.Chain, cfg, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts.Heights) != 4 || facts.Params.RequestTimeoutSeconds != 2 {
		t.Fatalf("facts %+v", facts)
	}
	for _, h := range facts.Heights {
		child, err := codec.DecodeExtra(res.Chain[h.Number+1].Header)
		if err != nil || h.Round != uint64(child.PrevRound) {
			t.Fatal("wrong decision scope")
		}
	}
	if _, err := InspectChain(res.Chain, cfg, 1, 5); err == nil {
		t.Fatal("last block without child accepted")
	}
	if _, err := InspectChain(nil, cfg, 1, 2); err == nil {
		t.Fatal("empty chain accepted")
	}
	saved := res.Chain[2].Header.ParentHash
	res.Chain[2].Header.ParentHash = types.Hash{}
	if _, err := InspectChain(res.Chain, cfg, 1, 4); err == nil {
		t.Fatal("different parent accepted")
	}
	res.Chain[2].Header.ParentHash = saved
	// From does not hide an unsupported warm-up configuration transition.
	changed := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100, ProposerPolicy: &pol}, []types.Transition{{Block: big.NewInt(2), WBFT: &types.WBFTParams{RequestTimeoutSeconds: 3}}}, types.GenesisInit{}, nil)
	if _, err := InspectChain(res.Chain, changed, 3, 4); err == nil {
		t.Fatal("configuration transition before comparison range accepted")
	}
}
