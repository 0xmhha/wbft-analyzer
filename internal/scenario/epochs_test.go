package scenario

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

func TestRecordedEpochMembershipRecomputesSelection(t *testing.T) {
	addresses := []types.Address{{19: 1}, {19: 2}, {19: 3}, {19: 4}, {19: 5}, {19: 6}}
	keys, err := TestValidators(addresses)
	if err != nil {
		t.Fatal(err)
	}
	sc := sim.Scenario{Validators: keys, Genesis: 4, Params: sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 4}, Epochs: []sim.EpochChange{{Block: 4, Candidates: []int{0, 1, 2, 3, 4, 5}}, {Block: 8, Candidates: []int{0, 1, 3, 4, 5}}}, Until: sim.Stop{Height: 10, Duration: time.Minute}}
	res, err := sim.Run(context.Background(), sc, sim.Output{})
	if err != nil || len(res.Violations) > 0 {
		t.Fatal(res.Violations, err)
	}
	gen, err := codec.DecodeExtra(res.Chain[0].Header)
	if err != nil {
		t.Fatal(err)
	}
	pol := uint64(0)
	cfg := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 4, ProposerPolicy: &pol}, nil, types.GenesisInit{Validators: gen.EpochInfo.ValidatorAddresses(), BLSPublicKeys: gen.EpochInfo.BLSPublicKeys}, nil)
	facts, err := InspectChain(res.Chain, cfg, 1, 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts.Validators) != 6 || facts.GenesisCount != 4 || len(facts.Epochs) != 2 || len(facts.Issues) != 0 || !facts.Epochs[0].HeaderInputsVerified || !facts.Epochs[1].HeaderInputsVerified {
		t.Fatal(facts)
	}
	for _, e := range facts.Epochs {
		original, err := codec.DecodeExtra(res.Chain[e.Block].Header)
		if err != nil || !reflect.DeepEqual(e.Validators, original.EpochInfo.ValidatorAddresses()) {
			t.Fatal(e, err)
		}
	}
	for i, k := range keys {
		if facts.Validators[i] != k.Address() {
			t.Fatal("candidate universe lost original order")
		}
	}
	mapped, err := ApplyEpochs(sim.Scenario{Validators: keys}, facts.Validators, facts.GenesisCount, facts.Epochs)
	if err != nil || !reflect.DeepEqual(mapped.Epochs, sc.Epochs) || mapped.Genesis != 4 {
		t.Fatal(mapped.Epochs, err)
	}
	// Recorded selection is evidence, not an override of another run's votes.
	altered := append([]RecordedEpoch(nil), facts.Epochs...)
	altered[0].Validators = []types.Address{addresses[5]}
	again, err := ApplyEpochs(sim.Scenario{Validators: keys}, facts.Validators, facts.GenesisCount, altered)
	if err != nil || !reflect.DeepEqual(again.Epochs, mapped.Epochs) {
		t.Fatal("recorded winners forced into replay", err)
	}
	bad := append([]RecordedEpoch(nil), facts.Epochs...)
	bad[0].HeaderInputsVerified = false
	if _, err := ApplyEpochs(sim.Scenario{Validators: keys}, facts.Validators, 4, bad); err == nil {
		t.Fatal("unverified epoch applied")
	}
	bad = append([]RecordedEpoch(nil), facts.Epochs...)
	bad[0].Candidates = []types.Address{{19: 99}}
	if _, err := ApplyEpochs(sim.Scenario{Validators: keys}, facts.Validators, 4, bad); err == nil {
		t.Fatal("unknown epoch node applied")
	}
	// A plausible selection with the wrong recorded order must be rejected.
	x, err := codec.DecodeExtra(res.Chain[4].Header)
	if err != nil {
		t.Fatal(err)
	}
	x.EpochInfo.Validators[0], x.EpochInfo.Validators[1] = x.EpochInfo.Validators[1], x.EpochInfo.Validators[0]
	x.EpochInfo.BLSPublicKeys[0], x.EpochInfo.BLSPublicKeys[1] = x.EpochInfo.BLSPublicKeys[1], x.EpochInfo.BLSPublicKeys[0]
	if err := codec.SetExtra(res.Chain[4].Header, x); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := inspectEpochs(res.Chain, cfg, 4, facts.Validators[:4]); err == nil {
		t.Fatal("recorded selection mismatch accepted")
	}
}
