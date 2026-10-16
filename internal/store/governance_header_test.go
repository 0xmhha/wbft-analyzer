package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
)

func TestGovernanceEpochEvidenceOrderedClaimsAndInputLimits(t *testing.T) {
	a := "0x" + strings.Repeat("1", 40)
	b := "0x" + strings.Repeat("2", 40)
	c := "0x" + strings.Repeat("3", 40)
	info := json.RawMessage(`{"Candidates":[{"Addr":"` + a + `"},{"Addr":"` + b + `"},{"Addr":"` + c + `"}],"Validators":[2,0]}`)
	fact := headers.Fact{Index: "50", EpochInfo: info, Validators: []string{a, b}}
	claim := governance.Epoch{Candidates: []string{a, b, c}, Validators: []string{c, a}, Added: []string{c}, Removed: []string{b}, NoKey: []string{a}}
	check := func(got *GovernanceEpochEvidence, candidates, validators, added, removed string) {
		t.Helper()
		if got.Candidates != candidates || got.Validators != validators || got.Added != added || got.Removed != removed || got.NoKeyStatus != "unverified_execution_keys" {
			t.Fatal(got)
		}
	}
	got := compareGovernanceEpoch(fact, claim)
	check(got, "matched", "matched", "matched", "matched")
	if got.Status != "available" || strings.Join(got.HeaderAdded, ",") != c || strings.Join(got.HeaderRemoved, ",") != b {
		t.Fatal(got)
	}
	claim.Candidates = []string{b, a, c}
	check(compareGovernanceEpoch(fact, claim), "mismatch", "matched", "matched", "matched")
	claim.Validators = []string{a, c}
	check(compareGovernanceEpoch(fact, claim), "mismatch", "mismatch", "matched", "matched")
	claim.Added = []string{}
	claim.Removed = []string{}
	check(compareGovernanceEpoch(fact, claim), "mismatch", "mismatch", "mismatch", "mismatch")
	fact.Index = "0"
	check(compareGovernanceEpoch(fact, claim), "mismatch", "mismatch", "unavailable", "unavailable")
	fact.Index = "50"
	fact.Validators = nil
	check(compareGovernanceEpoch(fact, claim), "mismatch", "mismatch", "unavailable", "unavailable")
	for _, raw := range []string{"", `{}`, `{"Candidates":[],"Validators":[]}`, `{"Candidates":[{"Addr":"` + a + `"}],"Validators":[1]}`, `{"Candidates":[{"Addr":"` + a + `"}],"Validators":[-1]}`, `[`, `null`} {
		fact.EpochInfo = json.RawMessage(raw)
		got := compareGovernanceEpoch(fact, claim)
		check(got, "unavailable", "unavailable", "unavailable", "unavailable")
		want := "header_epoch_unavailable"
		if raw == "null" {
			want = "not_epoch"
		}
		if got.Status != want {
			t.Fatal(raw, got)
		}
	}
}
