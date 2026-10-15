package scenario

import (
	"strings"
	"testing"
)

func TestScenarioProvenancePinsInputsAndSeeds(t *testing.T) {
	p := Provenance{ModelSHA256: strings.Repeat("e", 64), Dataset: 1, Version: FitVersion, ChainSHA256: strings.Repeat("a", 64), CoreCommit: strings.Repeat("b", 40), Seeds: []int64{1, 2}, Inputs: []Input{{ID: "b", Kind: "journal", Node: "b", SHA256: strings.Repeat("c", 64)}, {ID: "a", Kind: "journal", Node: "a", SHA256: strings.Repeat("d", 64)}}}
	fixed, hash, err := SealProvenance(p)
	if err != nil {
		t.Fatal(err)
	}
	if fixed.Inputs[0].ID != "a" || p.Inputs[0].ID != "b" {
		t.Fatal("canonicalization mutated caller")
	}
	p.Inputs[0], p.Inputs[1] = p.Inputs[1], p.Inputs[0]
	_, same, err := SealProvenance(p)
	if err != nil || same != hash {
		t.Fatal("input order changed scope")
	}
	p.Seeds = []int64{2, 1}
	_, changed, err := SealProvenance(p)
	if err != nil || changed == hash {
		t.Fatal("seed order not pinned")
	}
	p.Seeds = []int64{1, 1}
	if _, _, err := SealProvenance(p); err == nil {
		t.Fatal("duplicate seed accepted")
	}
	p.Seeds = []int64{1, 2}
	p.ModelSHA256 = ""
	if _, _, err := SealProvenance(p); err == nil {
		t.Fatal("unbound model accepted")
	}
	p.ModelSHA256 = strings.Repeat("f", 64)
	_, modelChanged, err := SealProvenance(p)
	if err != nil || modelChanged == hash {
		t.Fatal("model parameters not pinned")
	}
	p.Seeds = []int64{1, 2}
	p.Inputs[0].SHA256 = strings.Repeat("e", 64)
	_, changed, err = SealProvenance(p)
	if err != nil || changed == hash {
		t.Fatal("input bytes not pinned")
	}
}

func TestEmpiricalProvenanceBindsAssumptionsAndSubstitutionSources(t *testing.T) {
	input := Input{ID: "wire", Kind: "frames", Node: "node", SHA256: strings.Repeat("a", 64)}
	p := Provenance{Mode: EmpiricalCoreModel, Assumptions: []string{"fake_application", "core_substitution"}, Substitutions: []CoreSubstitution{{Node: "node", Source: input, Policy: "all_improvements_off", SigningState: "fresh_test_keys_genesis_no_replay"}}, ModelSHA256: strings.Repeat("b", 64), Dataset: 1, Version: FitVersion, Inputs: []Input{input}, ChainSHA256: strings.Repeat("c", 64), CoreCommit: strings.Repeat("d", 40), Seeds: []int64{1, 2}}
	fixed, hash, err := SealProvenance(p)
	if err != nil || fixed.Mode != EmpiricalCoreModel || p.Assumptions[0] != "fake_application" {
		t.Fatal(fixed, err)
	}
	p.Assumptions = []string{"core_substitution", "fake_application"}
	_, same, err := SealProvenance(p)
	if err != nil || same != hash {
		t.Fatal("assumption order changed identity", err)
	}
	p.Assumptions = []string{"different_application", "core_substitution"}
	_, changed, err := SealProvenance(p)
	if err != nil || changed == hash {
		t.Fatal("assumption missing from identity", err)
	}
	p.Substitutions[0].Source.SHA256 = strings.Repeat("e", 64)
	if _, _, err := SealProvenance(p); err == nil {
		t.Fatal("unbound substitution source accepted")
	}
	p.Substitutions = nil
	p.Mode = DeclaredRuntimeModel
	if _, _, err := SealProvenance(p); err == nil {
		t.Fatal("empirical assumptions passed as declared policy")
	}
}
