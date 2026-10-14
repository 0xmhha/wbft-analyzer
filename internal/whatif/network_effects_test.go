package whatif

import (
	"testing"

	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func TestNetworkPlannerDoesNotReuseAnOldArrivalForRelocatedBytes(t *testing.T) {
	e, sender, _, records := networkFixture(t)
	bindings, err := e.BindNetwork("sender", sender, records, source.Clock{Model: "shared-host"})
	if err != nil {
		t.Fatal(err)
	}
	var root Question
	var action Action
	for q, a := range e.actions {
		root = q
		action = a
	}
	e.entryMonos = map[Source]string{root.Source: "1"}
	scope := NetworkScope{Status: "complete", Clock: "shared-host", Inputs: []NetworkInput{}}
	scope.Seal()
	planner := e.NewNetworkPlanner(bindings, scope)
	step := Step{Execution: "1", Mono: "1", Source: &root.Source, Actions: []Action{action}}
	effects, err := planner.Note(step)
	if err != nil || len(effects) != 1 || effects[0].Status != "unchanged_under_model" {
		t.Fatal(effects, err)
	}
	_, summary, err := planner.Finish(true, bindings)
	if err != nil || summary.Status != "unchanged_under_model" {
		t.Fatal(summary, err)
	}
	// The same signed bytes, produced by a generated execution at another
	// time, have no observed counterfactual receive to reuse.
	planner = e.NewNetworkPlanner(bindings, scope)
	step.Generated = true
	step.Source = nil
	step.Mono = "2"
	action.SigningOutput = &root
	step.Actions = []Action{action}
	effects, err = planner.Note(step)
	if err != nil || effects[0].Kind != "relocated" || effects[0].Status != "arrival_unproved" {
		t.Fatal(effects, err)
	}
	_, summary, err = planner.Finish(true, bindings)
	if err != nil || summary.Status != "unproved" || summary.FirstUnproved == nil || summary.ObservedRemovedArrival != nil {
		t.Fatal("old latency reused", summary, err)
	}
}

func TestNetworkPlannerOnlyDeletesOriginalIntentsAfterCompleteExecution(t *testing.T) {
	e, sender, _, records := networkFixture(t)
	bindings, err := e.BindNetwork("sender", sender, records, source.Clock{Model: "shared-host"})
	if err != nil {
		t.Fatal(err)
	}
	scope := NetworkScope{Status: "complete", Inputs: []NetworkInput{}}
	scope.Seal()
	planner := e.NewNetworkPlanner(bindings, scope)
	effects, summary, err := planner.Finish(false, bindings)
	if err != nil || len(effects) != 0 || summary.Status != "unproved" {
		t.Fatal("unexecuted suffix labeled removed", effects, summary, err)
	}
	planner = e.NewNetworkPlanner(bindings, scope)
	effects, summary, err = planner.Finish(true, bindings)
	if err != nil || len(effects) != 1 || effects[0].Kind != "removed" || summary.Status != "bounded_original_delivery" || summary.ObservedRemovedArrival == nil {
		t.Fatal(effects, summary, err)
	}
	// One observed recipient cannot resolve a second missing recipient.
	missing := bindings[0]
	missing.Status = "missing_receive"
	missing.Arrival = nil
	bindings = append(bindings, missing)
	planner = e.NewNetworkPlanner(bindings, scope)
	effects, summary, err = planner.Finish(true, bindings)
	if err != nil || summary.Status != "unproved" || summary.Unproved == 0 || effects[0].Status != "partly_observed_original_delivery" {
		t.Fatal("missing recipient hidden", effects, summary, err)
	}
}

func TestNetworkPlannerKeepsCommitInfluenceUnproved(t *testing.T) {
	e, sender, _, records := networkFixture(t)
	for q, a := range e.actions {
		a.Kind = "commit"
		a.Code = ""
		a.PayloadEvidence = "not_network"
		a.PayloadSHA256 = ""
		a.Recipients = []string{}
		a.RecipientEvidence = "not_network"
		a.Application = &q
		e.actions[q] = a
	}
	bindings, err := e.BindNetwork("sender", sender, records, source.Clock{Model: "shared-host"})
	if err != nil || len(bindings) != 1 || bindings[0].Status != "application_delivery_unproved" {
		t.Fatal(bindings, err)
	}
	planner := e.NewNetworkPlanner(bindings, NetworkScope{Status: "complete"})
	for _, a := range e.actions {
		effects, err := planner.Note(Step{Execution: "1", Mono: "2", Generated: true, Actions: []Action{a}})
		if err != nil || effects[0].Status != "application_delivery_unproved" {
			t.Fatal(effects, err)
		}
	}
	_, summary, err := planner.Finish(true, bindings)
	if err != nil || summary.Status != "unproved" || summary.FirstUnproved == nil {
		t.Fatal(summary, err)
	}
}
