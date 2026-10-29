package headers

import (
	"github.com/0xmhha/wbft/types"
	"testing"
)

func TestSuccessorTailKeepsOwnCopyWithoutDecision(t *testing.T) {
	a := "0x0000000000000000000000000000000000000001"
	f := Fact{Index: "7", Number: "7", Hash: "parent", Validators: []string{a}, Coinbase: a}
	c := Copy{Index: "7", Hash: "parent", Node: "one", Round: 3, Prepared: []int64{0}, Committed: []int64{0}}
	row, err := Derive(f, nil, &c, &types.ProposerPolicy{}, types.Address{})
	if err != nil {
		t.Fatal(err)
	}
	if row.DecisionRound != nil || row.ProofHash != nil || row.ExpectedProposer != nil || row.ProposerDiffers != nil || len(row.Missed) != 0 || row.RoundSource != "unknown" {
		t.Fatalf("node copy became network decision: %+v", row)
	}
	if row.Copy == nil || row.Copy.Round != 3 || row.Cells[0].Committed != nil || row.Cells[0].OwnCommitted == nil || !*row.Cells[0].OwnCommitted {
		t.Fatal(row)
	}
	child := Fact{ParentHash: "parent", Hash: "child", PrevRound: 0, PrevCommitted: []int64{0}}
	row, err = Derive(f, &child, &c, &types.ProposerPolicy{}, types.Address{})
	if err != nil || row.DecisionRound == nil || *row.DecisionRound != 0 || row.Copy.Round != 3 || row.RoundSource != "child_prev_round" || row.ProofHash == nil || *row.ProofHash != "child" {
		t.Fatal(row, err)
	}
}
