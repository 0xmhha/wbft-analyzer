package observation

import (
	"encoding/json"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft/observe/participation"
	"testing"
)

// Only unsigned RPC metadata is projected; no signed header is changed.
func TestSuccessorIndependentCopyRound(t *testing.T) {
	facts, calls := fixture()
	var records []participation.Record
	if err := json.Unmarshal(calls[0].Data, &records); err != nil {
		t.Fatal(err)
	}
	records[0].Round = "1"
	records[0].Rounds = []participation.Round{{Round: "1", Proposer: addr(2), Outcome: "committed"}}
	for i := range records[0].Validators {
		records[0].Validators[i].Round = "1"
		records[0].Validators[i].IsProposer = i == 1
	}
	var cp observe.Copy
	if err := json.Unmarshal(calls[1].Data, &cp); err != nil {
		t.Fatal(err)
	}
	cp.Round = 1
	calls[0].Data, _ = json.Marshal(records)
	calls[1].Data, _ = json.Marshal(cp)
	got, err := Build(facts, calls, addr(4))
	if err != nil || len(got.Rows) != 2 {
		t.Fatal(got, err)
	}
	for _, row := range got.Rows {
		if row.Status != "matched" || row.Proof.NetworkRound == nil || *row.Proof.NetworkRound != 0 {
			t.Fatalf("independent node round rejected: %+v", row)
		}
	}
	if got.Rows[1].Copy == nil || got.Rows[1].Copy.Round != 1 || got.Summary.Covered != 1 {
		t.Fatal(got)
	}
	// A conflicting record and its node copy still disagree, independently of the child.
	records[0].Round = "2"
	calls[0].Data, _ = json.Marshal(records)
	got, err = Build(facts, calls, addr(4))
	if err != nil || got.Rows[0].Status != "different" || got.Rows[1].Status != "matched" {
		t.Fatal(got, err)
	}
}
