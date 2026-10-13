package reexec

import (
	"context"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/consensus/inputlog"
)

func answerProtocolPlan(t *testing.T) Plan {
	p := warmupPlan(t)
	c := answerContext{"synthetic-source", "18446744073709551615", "0", "0x" + strings.Repeat("a", 64), "0x" + strings.Repeat("c", 64)}
	p.Contexts = map[int64]answerContext{12: c, 20: c}
	source := AnswerSource{Ordinal: 12, File: "00000000000000000000.wal", Run: c.writer, Engine: c.engine, Step: "1", Call: 1, Kind: int(inputlog.EnvIsBadBlock), Key: "0x" + strings.Repeat("d", 64)}
	p.Answers = map[string]recordedAnswer{answerID(c.writer, c.engine, "1", 1): {Source: source, Context: c}}
	return p
}
func TestContextPolicyRetainsVerifiedBorrowedSourceAndCounterfactualStatus(t *testing.T) {
	p := answerProtocolPlan(t)
	h := testHelper(t, "answers_valid")
	h.AnswerScope = "context"
	var selected []Step
	r, err := Execute(context.Background(), p, h, func(s Step) error { selected = append(selected, s); return nil })
	if err != nil || r.Mode != "counterfactual" || r.Status != "counterfactual" || r.AnswerScope != "context" || r.Matches != 1 || len(selected) != 1 {
		t.Fatal(r, selected, err)
	}
	s := selected[0]
	if !s.ContextAnswers || len(s.AnswerSources) != 1 || s.AnswerSources[0].Ordinal != 12 || s.AnswerSources[0].Step != "1" || s.Number != "2" {
		t.Fatal("borrowed source lost", s)
	}
}
func TestContextHelperRejectsUnsupportedPolicyAndForgedProvenance(t *testing.T) {
	for _, mode := range []string{"answers_old", "answers_bad_source", "answers_reuse", "answers_bad_flag", "answers_bad_mode"} {
		t.Run(mode, func(t *testing.T) {
			h := testHelper(t, mode)
			h.AnswerScope = "context"
			r, err := Execute(context.Background(), answerProtocolPlan(t), h, func(Step) error { return nil })
			if err == nil || r.Status == "reproduced" {
				t.Fatal(r, err)
			}
			if mode == "answers_old" && r.Issue != "answer_scope_unsupported" {
				t.Fatal(r)
			}
		})
	}
	p := answerProtocolPlan(t)
	c := p.Contexts[20]
	c.hash = "0x" + strings.Repeat("e", 64)
	p.Contexts[20] = c
	h := testHelper(t, "answers_valid")
	h.AnswerScope = "context"
	if _, err := Execute(context.Background(), p, h, func(Step) error { return nil }); err == nil {
		t.Fatal("foreign head context accepted")
	}
}
func TestActualCoreContextSourceCoordinates(t *testing.T) {
	input, chain, genesis := simulationInput(t)
	p, err := Inspect(context.Background(), input, chain, "8282", genesis, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	h := testHelper(t, "core")
	h.AnswerScope = "context"
	calls := 0
	r, err := Execute(context.Background(), p, h, func(s Step) error {
		if !s.ContextAnswers {
			t.Fatal("context marker lost")
		}
		for _, a := range s.AnswerSources {
			calls++
			if a.Run != s.Run || a.Engine != s.Engine || a.Step != s.Number {
				t.Fatal(a, s)
			}
		}
		return nil
	})
	if err != nil || r.Status != "counterfactual" || r.Mode != "counterfactual" || calls == 0 {
		t.Fatal(r, calls, err)
	}
}
