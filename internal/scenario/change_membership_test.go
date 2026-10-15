package scenario

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
)

func membershipFixture(t *testing.T) (sim.Scenario, NetworkChange) {
	t.Helper()
	sc := timingFixture(t)
	sc.Params.EpochLength = 4
	sc.Until.Height = 13
	sc.Epochs = []sim.EpochChange{{Block: 4, Candidates: []int{0, 1, 2, 3}}, {Block: 8, Candidates: []int{0, 1, 2, 3}}, {Block: 12, Candidates: []int{0, 1, 2, 3}}}
	m := &MembershipChange{Policy: "replace_from_first_epoch", Nodes: []MembershipNode{{Alias: "test-new", Model: SyntheticCompatModel, StartNS: int64(2 * time.Second), Timing: MembershipTiming{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, MaxRequestTimeoutSeconds: 3}, BuildDelay: []MembershipDuration{{NS: int64(time.Millisecond)}}, ImportDelay: []MembershipDuration{{NS: int64(time.Millisecond)}}}}, Links: []MembershipLink{}, Epochs: []MembershipEpoch{{Block: 4, Candidates: []int{0, 1, 2, 3, 4}}, {Block: 8, Candidates: []int{0, 2, 3, 4}}}}
	for n := 0; n < 4; n++ {
		m.Links = append(m.Links, MembershipLink{From: n, To: 4, Delays: []MembershipDuration{{NS: int64(time.Millisecond)}}}, MembershipLink{From: 4, To: n, Delays: []MembershipDuration{{NS: int64(time.Millisecond)}}})
	}
	return sc, NetworkChange{Kind: "synthetic_membership", ToNS: int64(sc.Until.Duration), Membership: m}
}

func TestMembershipPreservesBaselineKeysGenesisAndSchedulePolicy(t *testing.T) {
	sc, c := membershipFixture(t)
	c.Membership.Links[0].LossPPM = 125000
	c.Membership.Links[0].Delays = []MembershipDuration{{NS: 1000000}, {NS: 2000000}}
	before, err := ExecutionHash(sc)
	if err != nil {
		t.Fatal(err)
	}
	changed, effect, hash, err := ApplyMembershipChange(sc, c)
	if err != nil || len(hash) != 64 || effect == nil {
		t.Fatal(effect, hash, err)
	}
	if changed.Genesis != 4 || len(changed.Validators) != 5 || !reflect.DeepEqual(changed.Validators[:4], sc.Validators) || !reflect.DeepEqual(changed.Nodes[:4], sc.Nodes) || !reflect.DeepEqual(changed.Links[:12], sc.Links) || !reflect.DeepEqual(changed.Schedule, sc.Schedule) || !reflect.DeepEqual(changed.App, sc.App) {
		t.Fatal("baseline keys or unchanged model inputs changed")
	}
	if len(effect.RemovedEpochs) != 3 || len(effect.RetainedEpochs) != 0 || len(changed.Epochs) != 2 || changed.Epochs[0].Candidates[4] != 4 || changed.Epochs[1].Candidates[1] != 2 {
		t.Fatal("replacement or candidate order lost", effect)
	}
	if effect.BaselineSHA256 != before || effect.CounterfactualSHA256 == before || len(effect.SyntheticNodes) != 1 || effect.SyntheticNodes[0].Index != 4 || effect.SyntheticNodes[0].Address == sc.Validators[0].Address().Hex() {
		t.Fatal("synthetic identity not retained", effect)
	}
	link := changed.Links[12]
	if len(changed.Links) != 20 || link.From != sc.Validators[0].Address() || link.To != changed.Validators[4].Address() || link.Loss != 0.125 || !reflect.DeepEqual(link.Delay, []time.Duration{time.Millisecond, 2 * time.Millisecond}) {
		t.Fatal("explicit new direction, loss or delay samples changed", link)
	}
	repeated, _, _, err := ApplyMembershipChange(sc, c)
	if err != nil || !reflect.DeepEqual(repeated.Validators, changed.Validators) {
		t.Fatal("synthetic test identity is not deterministic", err)
	}
	c.Membership.Policy = "merge"
	c.Membership.Epochs = c.Membership.Epochs[:1]
	merged, e, _, err := ApplyMembershipChange(sc, c)
	if err != nil || len(merged.Epochs) != 3 || len(e.RemovedEpochs) != 1 || len(e.RetainedEpochs) != 2 || !reflect.DeepEqual(merged.Epochs[1], sc.Epochs[1]) {
		t.Fatal("later recorded membership not retained", e, err)
	}
	c.Membership.Nodes[0].Timing.BlockPeriodSeconds = 9
	c.Membership.Nodes[0].BuildDelay[0].NS = 999
	c.Membership.Links[0].Delays[0].NS = 999
	c.Membership.Epochs[0].Candidates[0] = 4
	if *changed.Nodes[4].Timing.BlockPeriodSeconds != 1 || changed.Nodes[4].BuildDelay[0] != time.Millisecond || changed.Epochs[0].Candidates[0] != 0 || changed.Links[12].Delay[0] != time.Millisecond {
		t.Fatal("counterfactual aliases caller request")
	}
	after, err := ExecutionHash(sc)
	if err != nil || before != after {
		t.Fatal("baseline execution identity changed", before, after, err)
	}
}

func TestMembershipUsesOfficialEpochSelectionAndActualNodeStarts(t *testing.T) {
	sc, c := membershipFixture(t)
	changed, _, _, err := ApplyMembershipChange(sc, c)
	if err != nil {
		t.Fatal(err)
	}
	err = runSeedsWithMembership(context.Background(), changed, []int64{1, 2}, 1, 13, true, false, c.Membership, func(r SeedResult) error {
		if r.Status != "complete" || r.Violations != 0 || len(r.Execution.Nodes) != 5 || r.Execution.Membership == nil || len(r.Execution.Membership.UnobservedRequests) != 0 {
			t.Fatalf("official membership execution incomplete: %+v", r)
		}
		observed := r.Execution.Membership
		if observed.Scope != "longest_result_chain_not_each_node" || len(observed.Epochs) != 4 {
			t.Fatal("incorrect evidence scope", observed)
		}
		for _, e := range observed.Epochs {
			want := 4
			if e.Block == 4 {
				want = 5
			}
			if len(e.Candidates) != want || len(e.Validators) != want || !e.NextBlockObserved || e.GovernsFrom != e.Block+1 || len(e.BlockHash) != 66 {
				t.Fatal("actual header selection missing", e)
			}
			seen := map[int]bool{}
			for _, v := range e.Validators {
				seen[v.Node] = true
				if e.Candidates[v.Candidate].Node != v.Node {
					t.Fatal("candidate and validator indices conflated", e)
				}
			}
			if e.Block == 0 && seen[4] || e.Block >= 4 && !seen[4] || e.Block >= 8 && seen[1] {
				t.Fatal("addition/removal not observed in actual header", e)
			}
		}
		found := false
		for _, start := range r.Execution.Lifecycle.Starts {
			if start.Node == 4 {
				found = true
				if start.AtNS != int64(2*time.Second) || start.Status != "started" || start.WALRecords == nil || *start.WALRecords != 0 {
					t.Fatal("synthetic startup differs", start)
				}
			}
		}
		if !found {
			t.Fatal("actual synthetic node startup missing")
		}
		for _, node := range r.Execution.Nodes {
			if node.Head < 13 {
				t.Fatal("membership or synchronization did not progress", node)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMembershipRejectsIncompleteOrOutOfScopeModels(t *testing.T) {
	cases := map[string]func(*sim.Scenario, *NetworkChange){
		"missing edge":        func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Links = c.Membership.Links[1:] },
		"duplicate edge":      func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Links[0] = c.Membership.Links[1] },
		"recorded edge":       func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Links[0].To = 1 },
		"unknown endpoint":    func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Links[0].From = 5 },
		"complete loss":       func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Links[0].LossPPM = 1000000 },
		"unknown candidate":   func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Epochs[0].Candidates[4] = 5 },
		"duplicate candidate": func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Epochs[0].Candidates[4] = 0 },
		"non epoch":           func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Epochs[0].Block = 3 },
		"past stop":           func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Epochs[1].Block = 16 },
		"late startup":        func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Nodes[0].StartNS = c.ToNS },
		"missing timing":      func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Nodes[0].Timing.RequestTimeoutSeconds = 0 },
		"unknown model":       func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Nodes[0].Model = "other" },
		"empty app":           func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Nodes[0].BuildDelay = nil },
		"negative delay":      func(_ *sim.Scenario, c *NetworkChange) { c.Membership.Links[0].Delays[0].NS = -1 },
		"window only":         func(_ *sim.Scenario, c *NetworkChange) { c.FromNS = 1 },
		"irrelevant field":    func(_ *sim.Scenario, c *NetworkChange) { c.Node = indexPointer(0) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			sc, c := membershipFixture(t)
			mutate(&sc, &c)
			if _, _, _, err := ApplyMembershipChange(sc, c); err == nil {
				t.Fatal("invalid membership accepted")
			}
		})
	}
}

func TestMembershipStrictJSONAndHistoricalDefaults(t *testing.T) {
	_, c := membershipFixture(t)
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var decoded NetworkChange
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{`"start_ns":"2000000000"`, `"start_ns":2000000000`}, {`"loss_ppm":"0"`, `"loss_ppm":null`}, {`"from":0`, `"From":0`}, {`"model":"unmeasured_compat"`, `"model":"unmeasured_compat","private_key":"x"`}, {`"ns":"1000000"`, `"ns":null`}, {`"nodes":[`, `"unknown":true,"nodes":[`}} {
		invalid := strings.Replace(string(raw), pair[0], pair[1], 1)
		if invalid == string(raw) {
			t.Fatal("mutation did not apply", pair)
		}
		if json.Unmarshal([]byte(invalid), &decoded) == nil {
			t.Fatal("invalid JSON accepted", pair)
		}
	}
	for _, raw := range []string{`{"kind":"cut_outgoing","node":0,"from_ns":0,"to_ns":1,"membership":null}`, `{"kind":"synthetic_membership","from_ns":0,"to_ns":1,"membership":null}`} {
		if json.Unmarshal([]byte(raw), &decoded) == nil {
			t.Fatal("irrelevant or null membership accepted")
		}
	}
	encoded, err := json.Marshal(SeedExecution{})
	if err != nil || strings.Contains(string(encoded), "membership") {
		t.Fatal("old seed JSON changed", string(encoded), err)
	}
}

func TestMembershipRetainsRealResultsWhenRequestedEpochsAreNotReached(t *testing.T) {
	sc, c := membershipFixture(t)
	changed, _, _, err := ApplyMembershipChange(sc, c)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the result collector with an early actual stop, independently
	// of enqueue bounds, rather than fabricating an epoch from the request.
	changed.Until.Height = 3
	var control SeedResult
	if err := RunSeeds(context.Background(), changed, []int64{7}, 1, 3, func(r SeedResult) error { control = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := runSeedsWithMembership(context.Background(), changed, []int64{7}, 1, 3, true, false, c.Membership, func(r SeedResult) error {
		if r.Status != "partial" || len(r.Execution.Membership.UnobservedRequests) != 2 || len(r.Execution.Membership.Epochs) != 1 {
			t.Fatal("unreached epoch became a successful observation", r.Execution.Membership, r.Status)
		}
		if !reflect.DeepEqual(r.Heights, control.Heights) || !reflect.DeepEqual(r.Execution.Nodes, control.Execution.Nodes) || !reflect.DeepEqual(r.Execution.Violations, control.Execution.Violations) || r.SimulationNS != control.SimulationNS {
			t.Fatal("observation rewrote real simulator outcomes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMembershipRemovalWithoutSyntheticNodesKeepsRecordedRuntime(t *testing.T) {
	sc, c := membershipFixture(t)
	c.Membership.Nodes = []MembershipNode{}
	c.Membership.Links = []MembershipLink{}
	c.Membership.Epochs = []MembershipEpoch{{Block: 4, Candidates: []int{3, 0, 2}}}
	changed, effect, _, err := ApplyMembershipChange(sc, c)
	if err != nil || len(effect.SyntheticNodes) != 0 || !reflect.DeepEqual(sc.Nodes, changed.Nodes) || !reflect.DeepEqual(sc.Links, changed.Links) {
		t.Fatal("removal changed node or link models", err)
	}
	if err := runSeedsWithMembership(context.Background(), changed, []int64{3}, 1, 13, true, false, c.Membership, func(r SeedResult) error {
		if r.Status != "complete" || r.Violations != 0 {
			t.Fatal("official removal failed", r.Status, r.Violations)
		}
		for _, e := range r.Execution.Membership.Epochs {
			if e.Block >= 4 {
				if len(e.Validators) != 3 || e.Candidates[0].Node != 3 {
					t.Fatal("removal order lost", e)
				}
				for _, v := range e.Validators {
					if v.Node == 1 {
						t.Fatal("removed node still a validator", e)
					}
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
