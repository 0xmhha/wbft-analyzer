package main

import "testing"

func TestRegistryOrderChangeIsNotUnchanged(t *testing.T) {
	a := RegistryCandidate{Address: "0x0000000000000000000000000000000000000101"}
	b := RegistryCandidate{Address: "0x0000000000000000000000000000000000000102"}
	before := RegistryRead{Status: "observed", State: &RegistryState{Address: "0x0000000000000000000000000000000000000201", CodeHash: validatorProfile.code.Hex(), Candidates: []RegistryCandidate{a, b}}}
	after := before
	state := *before.State
	state.Candidates = []RegistryCandidate{b, a}
	after.State = &state
	effects := registryEffects(before, after)
	if len(effects) != 1 || effects[0].Kind != "candidate_order_changed" || effects[0].Candidate != "" || effects[0].Before != nil || effects[0].After != nil {
		t.Fatal("candidate reorder was reported as unchanged", effects)
	}
	state.Candidates = []RegistryCandidate{a, b}
	after.State = &state
	if len(registryEffects(before, after)) != 0 {
		t.Fatal("unchanged order invented an effect")
	}
}
