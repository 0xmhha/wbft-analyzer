package observation

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft/observe/participation"
)

func addr(i int) string      { return fmt.Sprintf("0x%040x", i) }
func blockHash(i int) string { return fmt.Sprintf("0x%064x", i) }
func fixture() ([]headers.Fact, []observe.Call) {
	vs := []string{addr(1), addr(2), addr(3), addr(4)}
	facts := []headers.Fact{}
	for i := 0; i < 3; i++ {
		facts = append(facts, headers.Fact{Index: fmt.Sprint(i), Number: fmt.Sprint(i), Hash: blockHash(i + 1), ParentHash: blockHash(i), Validators: vs, Epoch: "0", Coinbase: addr(1), Policy: "0", LastProposer: addr(4), EpochInfo: json.RawMessage(`null`)})
	}
	facts[2].PrevPrepared = []int64{0, 1, 2}
	facts[2].PrevCommitted = []int64{0, 1, 2}
	rows := []participation.ValidatorRound{}
	for i, a := range vs {
		rows = append(rows, participation.ValidatorRound{Round: "0", Validator: a, Index: uint32(i), IsProposer: i == 0, InPrevPrepared: i < 3, InPrevCommitted: i < 3, SealedPrepared: i < 3, SealedCommitted: i < 3})
	}
	r := participation.Record{Height: "1", Hash: blockHash(2), Source: "header", Round: "0", Proposer: addr(1), Rounds: []participation.Round{{Round: "0", Proposer: addr(1), Outcome: "committed"}}, Validators: rows}
	xs := []uint32{0, 1, 2}
	cp := observe.Copy{Number: "1", Hash: blockHash(2), Round: 0, Path: "imported", Prepared: &xs, Committed: &xs}
	rc, _ := json.Marshal([]participation.Record{r})
	cc, _ := json.Marshal(cp)
	return facts, []observe.Call{{Ordinal: 1, Method: "wbft_participation", Status: "available", Data: rc}, {Ordinal: 2, Method: "wbft_headerCopy", Status: "available", Data: cc}}
}
func TestCanonicalBindingRoundMembersFlagsAndTotals(t *testing.T) {
	f, c := fixture()
	r, e := Build(f, c, addr(4))
	if e != nil || len(r.Rows) != 2 || r.Rows[0].Status != "matched" || r.Rows[1].Status != "matched" || r.Rows[1].Copy == nil || r.Summary.Covered != 1 || r.Summary.Status != "complete_comparison" {
		t.Fatal(r, e)
	}
	for _, check := range r.Summary.Checks {
		if check.Status != "matched" {
			t.Fatal(check)
		}
	}
	// The RPC node may have entered a higher round beyond the network decision.
	var records []participation.Record
	_ = json.Unmarshal(c[0].Data, &records)
	records[0].Rounds = append(records[0].Rounds, participation.Round{Round: "1", Proposer: addr(2)})
	c[0].Data, _ = json.Marshal(records)
	r, e = Build(f, c, addr(4))
	if e != nil || r.Rows[0].Status != "matched" {
		t.Fatal(r, e)
	}
	found := false
	for _, check := range r.Summary.Checks {
		if strings.HasSuffix(check.Field, ":proposer_rounds") && check.Status == "different" {
			found = true
		}
	}
	if !found {
		t.Fatal("higher node round was silently pooled", r.Summary)
	}
}
func TestFullNumberAliasMissingCarrierAndCopyRoundRemainSeparate(t *testing.T) {
	f, c := fixture()
	f[1].Number = "18446744073709551617"
	f[2].Number = "18446744073709551618"
	var records []participation.Record
	_ = json.Unmarshal(c[0].Data, &records)
	records[0].Height = f[1].Number
	c[0].Data, _ = json.Marshal(records)
	var cp observe.Copy
	_ = json.Unmarshal(c[1].Data, &cp)
	cp.Number = f[1].Number
	c[1].Data, _ = json.Marshal(cp)
	r, e := Build(f, c, addr(4))
	if e != nil || r.Rows[1].Status != "matched" || r.Rows[1].Copy.Index != "1" {
		t.Fatal("full height was narrowed", r, e)
	}
	r, e = Build(f[:2], c, addr(4))
	if e != nil || r.Rows[0].Status != "unknown" || r.Rows[0].Proof.NetworkRound != nil || r.Rows[1].Status != "matched" || r.Rows[1].OwnRound == nil {
		t.Fatal("own round replaced missing network round", r, e)
	}
	// A canonical number alias is ambiguous, even when one hash happens to match.
	alias := f[1]
	alias.Index = "9"
	alias.Hash = blockHash(10)
	f = append(f, alias)
	r, e = Build(f, c, addr(4))
	if e != nil || r.Rows[1].Status != "different" || r.Rows[1].Copy != nil {
		t.Fatal("alias chose a convenient hash", r, e)
	}
}
func TestConflictsNeverBecomeBoundCopiesAndDoNotHideComparisons(t *testing.T) {
	for _, change := range []func([]headers.Fact, []observe.Call){
		func(f []headers.Fact, c []observe.Call) { f[0].Hash = blockHash(99) },
		func(f []headers.Fact, c []observe.Call) { f[2].ParentHash = blockHash(99) },
		func(f []headers.Fact, c []observe.Call) {
			var cp observe.Copy
			_ = json.Unmarshal(c[1].Data, &cp)
			cp.Round = 1
			c[1].Data, _ = json.Marshal(cp)
		},
		func(f []headers.Fact, c []observe.Call) {
			var cp observe.Copy
			_ = json.Unmarshal(c[1].Data, &cp)
			xs := []uint32{0, 0, 9}
			cp.Committed = &xs
			c[1].Data, _ = json.Marshal(cp)
		},
	} {
		f, c := fixture()
		change(f, c)
		r, e := Build(f, c, addr(4))
		if e != nil || r.Rows[1].Status == "matched" || r.Rows[1].Copy != nil {
			t.Fatal(r, e)
		}
	}
	f, c := fixture()
	var records []participation.Record
	_ = json.Unmarshal(c[0].Data, &records)
	records[0].Validators[0].InPrevCommitted = false
	c[0].Data, _ = json.Marshal(records)
	r, e := Build(f, c, addr(4))
	if e != nil || r.Rows[0].Status != "different" || r.Summary.Covered != 1 {
		t.Fatal("disagreement excluded from canonical denominator", r, e)
	}
	found := false
	for _, check := range r.Summary.Checks {
		if check.Field == addr(1)+":previous_committed" && check.Status == "different" {
			found = true
		}
	}
	if !found {
		t.Fatal(r.Summary)
	}
}

func TestProjectionLimitsAndInvalidCanonicalPolicy(t *testing.T) {
	f, c := fixture()
	f[1].Policy = "9"
	r, e := Build(f, c, addr(4))
	if e != nil || r.Rows[1].Copy != nil || r.Summary.Covered != 0 {
		t.Fatal("invalid policy used for independent totals", r, e)
	}
	f, c = fixture()
	calls := make([]observe.Call, 4096)
	for i := range calls {
		calls[i] = c[1]
	}
	calls[0] = c[0]
	var records []participation.Record
	_ = json.Unmarshal(c[0].Data, &records)
	records = append(records, records[0])
	calls[0].Data, _ = json.Marshal(records)
	if _, e = Build(f, calls, addr(4)); e == nil {
		t.Fatal("output limit did not run before expansion")
	}
}
