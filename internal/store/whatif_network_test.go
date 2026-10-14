package store

import (
	"context"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

func TestNetworkEffectFailureRollsBackItsExecutionAndKeepsOriginalEvidence(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	seconds := "2"
	id, err := s.BeginWhatif(ctx, WhatifRun{Dataset: dataset, Input: "journal", ChainSHA: strings.Repeat("b", 64), SourceSHA: strings.Repeat("a", 64), HelperSHA: strings.Repeat("c", 64), Policy: whatif.Policy{Request: &seconds}}, "private")
	if err != nil {
		t.Fatal(err)
	}
	origin := whatif.Source{Writer: "synthetic", Engine: "9007199254740993", Step: "9007199254740994", Ordinal: "3"}
	h, r := "1", "0"
	action := whatif.Action{Output: "1", Kind: "broadcast", SHA256: strings.Repeat("e", 64), Height: &h, Round: &r, Code: "19", Recipients: []string{}, RecipientEvidence: "validator_set", PayloadEvidence: "unsigned_request"}
	step := whatif.Step{Actions: []whatif.Action{action}, RecordedActions: []whatif.Action{}, ParentOutput: "0", Outputs: 1, Execution: "1", Mono: "0", Parent: "0", ArmExecution: "0", Source: &origin, Input: "start", Digest: "0x" + strings.Repeat("d", 64), Comparable: true, Counterfactual: true, Model: whatif.Model}
	effect := whatif.NetworkEffect{ID: "2", Kind: "added", Status: "arrival_unproved", ActionKind: "broadcast", Current: &whatif.OutputPosition{Execution: "1", Output: "1", Mono: "0"}, Bindings: []string{}}
	if err = s.PutWhatifStepWithEffects(ctx, id, step, []whatif.NetworkEffect{effect}); err == nil {
		t.Fatal("skipped effect sequence accepted")
	}
	rows, err := s.WhatifResults(ctx, id, 0, 10)
	if err != nil || len(rows) != 0 {
		t.Fatal("unlinked execution survived failed transaction", rows, err)
	}
	effect.ID = "1"
	if err = s.PutWhatifStepWithEffects(ctx, id, step, []whatif.NetworkEffect{effect}); err != nil {
		t.Fatal(err)
	}
	effects, err := s.WhatifNetworkEffects(ctx, id, 0, 10)
	if err != nil || len(effects) != 1 || effects[0].Current.Execution != "1" {
		t.Fatal(effects, err)
	}
	if err = s.PutWhatifStepWithEffects(ctx, id, step, []whatif.NetworkEffect{effect}); err == nil {
		t.Fatal("duplicate execution/effect accepted")
	}
	binding := whatif.NetworkBinding{Original: whatif.Question{Source: origin, Output: "1"}, Kind: "broadcast", Sender: "0x" + strings.Repeat("1", 40), Recipient: "0x" + strings.Repeat("2", 40), Status: "missing_send"}
	if err = s.PutWhatifNetworkBindings(ctx, id, []whatif.NetworkBinding{binding}); err != nil {
		t.Fatal(err)
	}
	bindings, err := s.WhatifNetworkBindings(ctx, id, 0, 1)
	if err != nil || len(bindings) != 1 || bindings[0].Evidence.Original.Source.Engine != origin.Engine {
		t.Fatal("large original coordinate changed", bindings, err)
	}
	removed := whatif.NetworkEffect{ID: "2", Kind: "removed", Status: "original_delivery_unproved", ActionKind: "broadcast", Original: &whatif.Question{Source: origin, Output: "1"}, Bindings: []string{"1"}}
	if err = s.FinishWhatifWithNetwork(ctx, id, whatif.Summary{Status: "completed", Model: whatif.Model}, []whatif.NetworkEffect{removed}); err == nil {
		t.Fatal("invalid completion accepted")
	}
	remaining, err := s.WhatifNetworkEffects(ctx, id, 1, 10)
	if err != nil || len(remaining) != 0 {
		t.Fatal("removed suffix survived failed completion", remaining, err)
	}
	if err = s.FinishWhatif(ctx, id, whatif.Summary{Status: "partial", Model: whatif.Model}); err != nil {
		t.Fatal(err)
	}
	effect.ID = "2"
	effect.Current = nil
	effect.Kind = "removed"
	if err = s.PutWhatifNetworkEffects(ctx, id, []whatif.NetworkEffect{effect}); err == nil {
		t.Fatal("finalized network evidence changed")
	}
}
