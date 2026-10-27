package reexec

import (
	"io"
	"testing"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

// A normal decided simulation supplies real recorded lookup answers. The
// inspector indexes application responses separately from those authorities.
func TestPriorHeadNormalRecordedAuthoritiesReplay(t *testing.T) {
	nodes := make([]sim.NodeSpec, 4)
	for i := range nodes {
		nodes[i] = sim.NodeSpec{Options: consensus.Options{Improvements: consensus.RestartSafety.With(consensus.BindPriorHead)}, Profile: "compat", ReplayWAL: true}
	}
	prepared, chain, genesis := simulationInputWithOptions(t, nodes)
	rd, err := journal.OpenReader(nil, prepared.Input.Path)
	if err != nil {
		t.Fatal(err)
	}
	lookups := 0
	for {
		rec, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if step, ok := rec.Body.(*journal.StepRec); ok {
			for _, raw := range step.Env {
				call, err := inputlog.DecodeEnv(raw)
				if err != nil {
					t.Fatal(err)
				}
				if call.Kind == inputlog.EnvValidatorsAt {
					lookups++
				}
			}
		}
	}
	if lookups < 4 {
		t.Fatal("normal historical and successor lookups missing", lookups)
	}
	plan, err := Inspect(t.Context(), prepared, chain, "8282", genesis, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range plan.Heights {
		if row.Status != "complete" {
			t.Fatal("recorded authority became an application-answer gap", row)
		}
	}
	for _, answer := range plan.Answers {
		if answer.Source.Kind == int(inputlog.EnvValidatorsAt) {
			t.Fatal("authority escaped into application answer pool")
		}
	}
	for _, scope := range []string{"step", "context"} {
		h := testHelper(t, "core")
		h.AnswerScope = scope
		steps := 0
		result, err := Execute(t.Context(), plan, h, func(step Step) error {
			steps++
			if step.Class != "match" {
				t.Error("normal recorded authority replay diverged", step)
			}
			return nil
		})
		if err != nil || steps == 0 || result.Mismatches != 0 {
			t.Fatal("closed source consumption failed", scope, result, err)
		}
	}
}
