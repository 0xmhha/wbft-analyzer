package reexec

import (
	"io"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// A normal simulator journal records core steps and the exact local mask.
// Reading or replaying it does not reexecute application header assembly.
func TestEpochPresenceOptionRecordedCoreScope(t *testing.T) {
	for _, choice := range []struct {
		name string
		mask consensus.ImprovementSet
	}{
		{"off", consensus.RestartSafety},
		{"on", consensus.RestartSafety.With(consensus.CheckEpochInfoPresence)},
		{"bound-off", consensus.RestartSafety.With(consensus.WatchCommittedImport)},
		{"bound-on", consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.CheckEpochInfoPresence)},
	} {
		t.Run(choice.name, func(t *testing.T) {
			nodes := make([]sim.NodeSpec, 4)
			for i := range nodes {
				nodes[i] = sim.NodeSpec{Options: consensus.Options{Improvements: choice.mask}, Profile: "compat", ReplayWAL: true}
			}
			prepared, chain, genesis := simulationInputWithOptions(t, nodes)
			rd, err := journal.OpenReader(nil, prepared.Input.Path)
			if err != nil {
				t.Fatal(err)
			}
			segments, records := 0, 0
			var self types.Address
			for {
				rec, err := rd.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				records++
				if segment, ok := rec.Body.(*journal.SegmentRec); ok {
					segments++
					self = segment.Self
					if segment.Core.Improvements != uint64(choice.mask) {
						t.Fatal("original declaration changed")
					}
				}
			}
			if segments == 0 || records <= segments {
				t.Fatal("normal original core records missing", segments, records)
			}
			node, _, err := scenario.InspectNodeOptions(t.Context(), prepared.Input.Path, self)
			if err != nil {
				t.Fatal(err)
			}
			if node.Improvements != uint64(choice.mask) || node.RuntimeEvidence != "" || node.ReplayWAL || node.SignFloor != nil {
				t.Fatal("reader changed mask or inferred unrecorded runtime", node)
			}
			plan, err := Inspect(t.Context(), prepared, chain, "8282", genesis, 1, 2)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Heights) != 2 || len(plan.Steps) == 0 {
				t.Fatal("normal core scope missing")
			}
			for _, row := range plan.Heights {
				if row.Status != "complete" {
					t.Fatal("normal core steps became partial", row)
				}
			}
			steps := 0
			result, err := Execute(t.Context(), plan, testHelper(t, "core"), func(step Step) error {
				steps++
				if step.Class != "match" {
					t.Error("recorded core step differs", step)
				}
				return nil
			})
			if err != nil || steps == 0 || result.Mismatches != 0 || result.Matches != int64(steps) {
				t.Fatal("declared core replay failed", result, steps, err)
			}
			t.Logf("recorded_epoch_presence choice=%s segments=%d core_steps=%d exact_mask=%d header_presence_reexecuted=false physical_reconstruction=false", choice.name, segments, steps, choice.mask)
		})
	}
}
