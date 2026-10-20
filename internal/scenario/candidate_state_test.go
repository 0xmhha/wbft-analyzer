package scenario

import (
	"context"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

func TestCandidateStateWindowsAndFullActivation(t *testing.T) {
	for _, entry := range []struct {
		at   string
		want uint64
	}{{"0", 3}, {"4", 3}, {"5", 4}, {"18446744073709551616", 4}} {
		p := sim.Params{EpochLength: 4, RuleActivations: map[types.RuleName]string{types.EpochInfoInProposal: entry.at}}
		got, err := candidateInputBlock(p, 4)
		if err != nil || got != entry.want {
			t.Fatal(entry, got, err)
		}
		epoch, err := candidateSelectionEpoch(p, got)
		if err != nil || epoch != 4 {
			t.Fatal(entry, epoch, err)
		}
	}
	p := sim.Params{EpochLength: 1, RuleActivations: map[types.RuleName]string{types.EpochInfoInProposal: "0"}}
	if _, err := candidateSelectionEpoch(p, math.MaxUint64); err == nil {
		t.Fatal("candidate window wrapped")
	}
	if got, err := candidateInputBlock(p, 1); err != nil || got != 0 {
		t.Fatal(got, err)
	}
}

func TestRecordedParentCandidateEpochsDoNotShiftSelection(t *testing.T) {
	sc := timingFixture(t)
	sc.Params.EpochLength = 4
	sc.Params.RuleActivations = map[types.RuleName]string{types.EpochInfoInProposal: "0", types.CommittedEpochDiligence: "0"}
	sc.Epochs = []sim.EpochChange{{Block: 4, Candidates: []int{0, 1, 2}}}
	sc.Until = sim.Stop{Height: 10, Duration: time.Minute}
	directory := t.TempDir()
	original, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: directory})
	if err != nil || len(original.Violations) > 0 {
		t.Fatal(err, original)
	}
	cfg := recordedTestConfiguration(t, directory, sc.Validators[0])
	facts, err := InspectChain(original.Chain, cfg, 1, 9)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := ApplyEpochs(sc, facts.Validators, facts.GenesisCount, facts.Epochs)
	if err != nil || mapped.Epochs[0].Block != 3 || mapped.Epochs[1].Block != 7 {
		t.Fatal(mapped.Epochs, err)
	}
	replay, err := sim.Run(context.Background(), mapped, sim.Output{})
	if err != nil || len(replay.Violations) > 0 {
		t.Fatal(err, replay)
	}
	for _, number := range []uint64{4, 8} {
		want, err := codec.DecodeExtra(original.Chain[number].Header)
		if err != nil {
			t.Fatal(err)
		}
		got, err := codec.DecodeExtra(replay.Chain[number].Header)
		if err != nil || !reflect.DeepEqual(got.EpochInfo, want.EpochInfo) {
			t.Fatal("observed candidate membership shifted", number, err)
		}
	}
	change := NetworkChange{Kind: "synthetic_membership", ToNS: int64(sc.Until.Duration), Membership: &MembershipChange{Policy: "merge", Nodes: []MembershipNode{}, Links: []MembershipLink{}, Epochs: []MembershipEpoch{{Block: 4, Candidates: []int{0, 1, 2}}}}}
	changed, effect, _, err := ApplyMembershipChange(mapped, change)
	if err != nil || len(effect.CandidateInputs) == 0 || effect.EffectiveEpochs[0].Block != 4 || changed.Epochs[0].Block != 3 {
		t.Fatal(effect, err)
	}
	result, err := sim.Run(context.Background(), changed, sim.Output{})
	if err != nil || len(result.Violations) > 0 {
		t.Fatal(err, result)
	}
	extra, err := codec.DecodeExtra(result.Chain[4].Header)
	if err != nil || len(extra.EpochInfo.Candidates) != 3 {
		t.Fatal("request moved beyond selected epoch", err)
	}
}

func TestCandidateRequestDoesNotAlterEarlierEpoch(t *testing.T) {
	sc := timingFixture(t)
	sc.Params.EpochLength = 1
	sc.Params.RuleActivations = map[types.RuleName]string{types.EpochInfoInProposal: "4", types.CommittedEpochDiligence: "0"}
	change := NetworkChange{Kind: "synthetic_membership", ToNS: int64(sc.Until.Duration), Membership: &MembershipChange{Policy: "merge", Nodes: []MembershipNode{}, Links: []MembershipLink{}, Epochs: []MembershipEpoch{{Block: 4, Candidates: []int{0, 1, 2}}}}}
	if _, _, _, err := ApplyMembershipChange(sc, change); err == nil {
		t.Fatal("request silently changed the earlier legacy epoch")
	}
}
