package whatif

import (
	"strings"
	"testing"
)

func TestActionsBindWholeProducerSigningInputAndRecipients(t *testing.T) {
	producer := Source{"synthetic", "1", "1", "3"}
	signing := Source{"synthetic", "1", "2", "7"}
	height, round := "9007199254740993", "9007199254740994"
	a := Action{Output: "1", Kind: "broadcast", SHA256: strings.Repeat("a", 64), Height: &height, Round: &round, Code: "2", Recipients: []string{"0x" + strings.Repeat("b", 40)}, RecipientEvidence: "validator_set", PayloadSHA256: strings.Repeat("c", 64), PayloadEvidence: "recorded_signing_result", SigningInput: &signing, SigningOutput: &Question{producer, "1"}}
	e, err := NewEvidence([]Source{producer, signing})
	if err != nil {
		t.Fatal(err)
	}
	e.actions = map[Question]Action{{producer, "1"}: a}
	s := Step{Actions: []Action{a}, RecordedActions: []Action{a}, ParentOutput: "0", Execution: "1", Mono: "0", Parent: "0", ArmExecution: "0", Source: &producer, Input: "start", Digest: "0x" + strings.Repeat("d", 64), Outputs: 1, Comparable: true, Counterfactual: true, Model: Model}
	if err = e.Validate(s, 0); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"signing_as_producer", "different_signed_bytes", "different_recipients", "different_question", "truncated_original", "unknown_origin"} {
		c := s
		c.Actions = append([]Action(nil), s.Actions...)
		c.RecordedActions = append([]Action(nil), s.RecordedActions...)
		switch mutation {
		case "signing_as_producer":
			c.Actions[0].SigningOutput = &Question{signing, "1"}
		case "different_signed_bytes":
			c.Actions[0].PayloadSHA256 = strings.Repeat("e", 64)
		case "different_recipients":
			c.Actions[0].Recipients = []string{}
		case "different_question":
			c.Actions[0].SHA256 = strings.Repeat("f", 64)
		case "truncated_original":
			c.RecordedActions = []Action{}
		case "unknown_origin":
			c.Actions[0].SigningInput = &Source{"synthetic", "1", "2", "8"}
		}
		fresh := *e
		fresh.consumedSources = nil
		fresh.consumedSigning = nil
		fresh.executions = nil
		if fresh.Validate(c, 0) == nil {
			t.Fatal("fabricated output evidence accepted", mutation)
		}
	}
	if e.Complete() == nil {
		t.Fatal("missing retained input accepted as complete")
	}
	duplicate := s
	duplicate.Execution = "2"
	if e.Validate(duplicate, 1) == nil {
		t.Fatal("original source reused")
	}
	reused := s
	reused.Execution = "2"
	reused.Source = &signing
	reused.RecordedActions = []Action{}
	if e.Validate(reused, 1) == nil {
		t.Fatal("known signing result reused")
	}
	// A generated self delivery points to the actual execution's broadcast,
	// while its original signing input retains its independent ordinal.
	generated := Step{Actions: []Action{}, RecordedActions: []Action{}, ParentOutput: "1", Execution: "2", Mono: "1", Parent: "1", ArmExecution: "0", Cause: &producer, Signing: &signing, Generated: true, Input: "message", Digest: "0x" + strings.Repeat("d", 64), Counterfactual: true, Model: Model}
	if e.Validate(generated, 1) != nil {
		t.Fatal("known generated producer refused")
	}
	generated.ParentOutput = "2"
	if e.Validate(generated, 1) == nil {
		t.Fatal("nonexistent producer output accepted")
	}
	generated.ParentOutput = "1"
	e.executions["1"][0].Kind = "schedule"
	if e.Validate(generated, 1) == nil {
		t.Fatal("schedule mislabeled as signed message producer")
	}
}

func TestActionSchemaRefusesRawPayloadMissingRecipientsAndRoundedCoordinates(t *testing.T) {
	h, r, d := "9007199254740993", "0", "2"
	a := Action{Output: "1", Kind: "arm_timer", SHA256: strings.Repeat("a", 64), Height: &h, Round: &r, Timer: "1", Duration: &d, Recipients: []string{}, RecipientEvidence: "not_network", PayloadEvidence: "not_network"}
	if a.validate(0) != nil {
		t.Fatal("large exact view refused")
	}
	a.Recipients = nil
	if a.validate(0) == nil {
		t.Fatal("missing recipients accepted")
	}
	a.Recipients = []string{}
	a.Event = "unexpected-private-text"
	if a.validate(0) == nil {
		t.Fatal("unrelated event text accepted")
	}
	a.Event = ""
	h = "09"
	if a.validate(0) == nil {
		t.Fatal("rounded/ambiguous view accepted")
	}
}

func TestFailureEvidenceRequiresTheActualBroadcastProducer(t *testing.T) {
	source := Source{"synthetic", "1", "1", "3"}
	e, err := NewEvidence([]Source{source})
	if err != nil {
		t.Fatal(err)
	}
	e.executions = map[string][]Action{"1": {{Kind: "broadcast"}}}
	parent, output := "1", "1"
	if e.ValidateFailure("2", &parent, &output, &source, nil, 1, "signing_unavailable") != nil {
		t.Fatal("known signing failure refused")
	}
	if e.ValidateFailure("2", &parent, nil, &source, nil, 1, "signing_unavailable") == nil {
		t.Fatal("missing failure output accepted")
	}
	output = "2"
	if e.ValidateFailure("2", &parent, &output, &source, nil, 1, "signing_unavailable") == nil {
		t.Fatal("fabricated failure output accepted")
	}
	output = "1"
	e.executions["1"][0].Kind = "arm_timer"
	if e.ValidateFailure("2", &parent, &output, &source, nil, 1, "signing_unavailable") == nil {
		t.Fatal("timer output accepted as signing producer")
	}
}

func TestCompletionSeparatesReplacedTimeoutsFromMissingExternalSlots(t *testing.T) {
	external := Source{"synthetic", "1", "1", "3"}
	timeout := Source{"synthetic", "1", "2", "7"}
	e, err := NewEvidence([]Source{external, timeout})
	if err != nil {
		t.Fatal(err)
	}
	e.retiredTimers = map[Source]bool{timeout: true}
	if e.Complete() == nil {
		t.Fatal("missing external input accepted")
	}
	e.consumedSources = map[Source]bool{external: true}
	if e.Complete() != nil {
		t.Fatal("independently identified original timeout incorrectly required")
	}
	if len(e.RetiredTimers()) != 1 || e.RetiredTimers()[0] != timeout {
		t.Fatal("replaced timeout source lost")
	}
	e.consumedSources[timeout] = true
	if e.Complete() == nil {
		t.Fatal("original timeout counted as external source")
	}
}
