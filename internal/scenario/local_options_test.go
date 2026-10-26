package scenario

import (
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestRecordedLocalOptionMasksPreserveEvidence(t *testing.T) {
	address := types.Address{1}
	masks := []consensus.ImprovementSet{consensus.RestartSafety, consensus.RestartSafety.With(consensus.WatchCommittedImport), consensus.RestartSafety.With(consensus.AdvanceOnCommitFailure), consensus.RestartSafety.With(consensus.ResetHeightState), consensus.RestartSafety.With(consensus.ScanReadyBacklog), consensus.RestartSafety.With(consensus.ResetHeightState).With(consensus.ScanReadyBacklog), consensus.RestartSafety.With(consensus.CancelStaleRetries), consensus.RestartSafety.With(consensus.FollowHigherRoundChanges), consensus.RestartSafety.With(consensus.CancelStaleRetries).With(consensus.FollowHigherRoundChanges), consensus.RestartSafety.With(consensus.BindPreparedCertificate), consensus.RestartSafety.With(consensus.DropUnboundExtraSeals), consensus.RestartSafety.With(consensus.ResumeRoundProposals), consensus.RestartSafety.With(consensus.BindPreparedCertificate).With(consensus.DropUnboundExtraSeals).With(consensus.ResumeRoundProposals), consensus.RestartSafety.With(consensus.RefreshRoundCertificates), consensus.RestartSafety.With(consensus.ClearCurrentExtraSeals), consensus.RestartSafety.With(consensus.RefreshRoundCertificates).With(consensus.ClearCurrentExtraSeals), consensus.RestartSafety.With(consensus.ValidateRoundProposals), consensus.RestartSafety.With(consensus.CapInitialRoundTimeout), consensus.RestartSafety.With(consensus.UseFutureTimeAllowance), consensus.RestartSafety.With(consensus.LimitFutureProposalWait), consensus.RestartSafety.With(consensus.UseFutureTimeAllowance).With(consensus.LimitFutureProposalWait), consensus.RestartSafety.With(consensus.RequireInitialRoundBudget), consensus.RestartSafety.With(consensus.PreserveRoundDeadline), consensus.RestartSafety.With(consensus.RequireInitialRoundBudget).With(consensus.PreserveRoundDeadline), consensus.RestartSafety.With(consensus.KeepStoppedPeers), consensus.RestartSafety.With(consensus.BindFreshProposalAuthor), consensus.KnownImprovements(), 0, 1, 4, 1 << 19, 1 << 20, 1 << 21, 1 << 63}
	for _, profile := range []string{"", "compat", "improved"} {
		for _, mask := range masks {
			t.Run(fmt.Sprintf("%s/%d", profile, mask), func(t *testing.T) {
				directory := t.TempDir()
				writer, err := journal.Open(journal.Options{Dir: directory, Synchronous: true}, journal.Identity{Run: "synthetic-local-options", Self: address, Core: journal.CoreOptions{Self: address, ChainConfig: []byte(`{"chainId":7,"anzeon":{"wbft":{"epochLength":10}}}`), Profile: profile, Improvements: uint64(mask)}})
				if err != nil {
					t.Fatal(err)
				}
				if err = writer.Close(); err != nil {
					t.Fatal(err)
				}
				node, _, err := InspectNodeOptions(t.Context(), directory, address)
				unknown := mask & ^consensus.KnownImprovements() != 0
				missingSafety := mask&consensus.RestartSafety != consensus.RestartSafety
				if unknown || profile == "" && missingSafety {
					if err == nil {
						t.Fatal("unsupported recorded configuration accepted", node)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				evidence := "recorded"
				wantProfile := profile
				if profile == "" {
					wantProfile = "compat"
					evidence = "derived_restart_safety_flags"
					if mask != consensus.RestartSafety {
						evidence = "derived_recorded_node_flags"
					}
				}
				if node.Improvements != uint64(mask) || node.Profile != wantProfile || node.ProfileEvidence != evidence || node.RuntimeEvidence != "" || node.ReplayWAL || node.SignFloor != nil {
					t.Fatal("recorded mask or evidence scope changed", node)
				}
			})
		}
	}
}

func TestBuildPreservesKnownMasksAndRefusesUnknownFlags(t *testing.T) {
	params := sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 10}
	delay := []time.Duration{time.Millisecond}
	stop := sim.Stop{Height: 3, Duration: time.Minute}
	for _, profile := range []string{"compat", "improved"} {
		for _, mask := range []uint64{0, 3, 7, 11, 15, 16, 19, 32, 35, 51, 63, 64, 67, 128, 131, 195, 255, 256, 259, 512, 515, 1024, 1027, 1795, 2047, 2048, 2051, 4096, 4099, 6147, 8191, 8192, 8195, 16383, 16384, 16387, 32767, 32768, 32771, 65536, 65539, 98307, 131071, 131072, 131075, 262144, 262147, 393219, 524287, 524288, 524291, 1048575, 1048576, 1048579, 2097151, 2097152, 1 << 63} {
			nodes, links := completeFixture()
			nodes[0].Profile, nodes[0].Improvements = profile, mask
			sc, err := Build(nodes, links, params, delay, delay, stop)
			if consensus.ImprovementSet(mask) & ^consensus.KnownImprovements() != 0 {
				if err == nil {
					t.Fatal("unknown model flags accepted", profile, mask)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if sc.Nodes[0].Profile != profile || uint64(sc.Nodes[0].Options.Improvements) != mask {
				t.Fatal("exact model flags changed", profile, mask)
			}
		}
	}
}
