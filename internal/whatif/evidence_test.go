package whatif

import (
	"strings"
	"testing"
)

func TestEvidenceRequiresExactSourceOrdinalInsteadOfNearestStep(t *testing.T) {
	source := Source{Writer: "synthetic", Engine: "1", Step: "2", Ordinal: "7"}
	s := Step{Execution: "1", Mono: "0", Parent: "0", ArmExecution: "0", Source: &source, Input: "start", Digest: "0x" + strings.Repeat("a", 64), Comparable: true, Counterfactual: true, Model: Model}
	evidence, err := NewEvidence([]Source{source})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Validate(s, 0) != nil {
		t.Fatal("exact source refused")
	}
	wrong := source
	wrong.Ordinal = "8"
	s.Source = &wrong
	if evidence.Validate(s, 0) == nil {
		t.Fatal("unknown ordinal accepted")
	}
	s.Source = &source
	s.Answers = []Answer{{Writer: "synthetic", Engine: "1", Step: "2", Call: 1, Kind: 1, Key: "0x" + strings.Repeat("b", 64)}}
	if err = evidence.WithAnswers([]RecordedAnswer{{Source: source, Call: 1, Kind: 1, Key: s.Answers[0].Key}}); err != nil {
		t.Fatal(err)
	}
	if evidence.Validate(s, 0) != nil {
		t.Fatal("unique answer context refused")
	}

	originalKey := s.Answers[0].Key
	s.Answers[0].Key = "0x" + strings.Repeat("c", 64)
	if evidence.Validate(s, 0) == nil {
		t.Fatal("unknown argument key accepted")
	}
	s.Answers[0].Key = originalKey
	s.Answers[0].Call = 2
	if evidence.Validate(s, 0) == nil {
		t.Fatal("unknown call accepted")
	}
	s.Answers[0].Call = 1
	s.Questions = []Question{{source, "2"}}
	if evidence.Validate(s, 0) == nil {
		t.Fatal("nonexistent application question accepted")
	}
	evidence.questions = map[Question]bool{{source, "2"}: true}
	if evidence.Validate(s, 0) != nil {
		t.Fatal("known application question refused")
	}
	s.Questions = nil
	evidence, err = NewEvidence([]Source{source, wrong})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Validate(s, 0) == nil {
		t.Fatal("ambiguous answer coordinate accepted")
	}
}
