package reexec

import (
	"fmt"
	"io"
	"testing"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestRecordedLocalImportOptionsReplayBoundResults(t *testing.T) {
	for _, mask := range []consensus.ImprovementSet{consensus.RestartSafety.With(consensus.WatchCommittedImport), consensus.RestartSafety.With(consensus.AdvanceOnCommitFailure), consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.ResetHeightState), consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.ScanReadyBacklog), consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.CancelStaleRetries), consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.FollowHigherRoundChanges), consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.BindPreparedCertificate), consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.DropUnboundExtraSeals), consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.ResumeRoundProposals), consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.RefreshRoundCertificates), consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.ClearCurrentExtraSeals), consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.ValidateRoundProposals), consensus.RestartSafety.With(consensus.WatchCommittedImport).With(consensus.CapInitialRoundTimeout), consensus.KnownImprovements()} {
		t.Run(fmt.Sprintf("%d", mask), func(t *testing.T) {
			nodes := make([]sim.NodeSpec, 4)
			for i := range nodes {
				nodes[i] = sim.NodeSpec{Options: consensus.Options{Improvements: mask}, Profile: "compat", ReplayWAL: true}
			}
			prepared, chain, genesis := simulationInputWithOptions(t, nodes)
			reader, err := journal.OpenReader(nil, prepared.Input.Path)
			if err != nil {
				t.Fatal(err)
			}
			bound := 0
			for {
				record, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if segment, ok := record.Body.(*journal.SegmentRec); ok && segment.Core.Improvements != uint64(mask) {
					t.Fatal("journal mask changed")
				}
				step, ok := record.Body.(*journal.StepRec)
				if !ok || step.InputKind != inputlog.KindCommitResult {
					continue
				}
				decoded, err := inputlog.Decode(step.InputKind, step.Input, nil)
				if err != nil {
					t.Fatal(err)
				}
				result := decoded.(consensus.CommitResult)
				if result.View == nil || result.Hash == (consensus.CommitResult{}).Hash {
					t.Fatal("import attempt binding missing")
				}
				bound++
			}
			if bound == 0 {
				t.Fatal("bound import results missing")
			}
			plan, err := Inspect(t.Context(), prepared, chain, "8282", genesis, 1, 2)
			if err != nil {
				t.Fatal(err)
			}
			for _, height := range plan.Heights {
				if height.Status != "complete" {
					t.Fatal("bound input became partial", height)
				}
			}
			steps := 0
			result, err := Execute(t.Context(), plan, testHelper(t, "core"), func(step Step) error {
				steps++
				if step.Class != "match" {
					t.Error(step)
				}
				return nil
			})
			if err != nil || steps == 0 || result.Mismatches != 0 {
				t.Fatal("bound import replay diverged", result, err)
			}
		})
	}
}
