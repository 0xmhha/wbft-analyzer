package reexec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

// Normal decided chains supply the original ordered lookup answers. Neither
// replay scope infers an application answer or a physical recovery guarantee.
func TestValidatorStartNormalRecordedAuthoritiesAndFiveCounters(t *testing.T) {
	for _, mask := range []consensus.ImprovementSet{consensus.RestartSafety, consensus.RestartSafety.With(consensus.DeferValidatorStart), consensus.RestartSafety.With(consensus.DeferValidatorStart).With(consensus.BindPriorHead), consensus.KnownImprovements()} {
		t.Run(fmt.Sprint(uint64(mask)), func(t *testing.T) {
			nodes := make([]sim.NodeSpec, 4)
			for i := range nodes {
				nodes[i] = sim.NodeSpec{Options: consensus.Options{Improvements: mask}, Profile: "compat", ReplayWAL: true}
			}
			prepared, chain, genesis := simulationInputWithOptions(t, nodes)
			rd, err := journal.OpenReader(nil, prepared.Input.Path)
			if err != nil {
				t.Fatal(err)
			}
			lookups, starts := 0, 0
			var identity journal.Identity
			for {
				rec, err := rd.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if segment, ok := rec.Body.(*journal.SegmentRec); ok {
					identity = segment.Identity
					if segment.Core.Improvements != uint64(mask) {
						t.Fatal("selected mask changed")
					}
				}
				if step, ok := rec.Body.(*journal.StepRec); ok {
					if step.InputKind == inputlog.KindStart {
						starts++
						if mask.Has(consensus.DeferValidatorStart) && (len(step.TimerGens) != 5 || !mask.Has(consensus.ValidateRoundProposals) && step.TimerGens[3] != 0) {
							t.Fatal("actual selected pre-start profile lost", step.TimerGens)
						}
					}
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
			if starts == 0 || mask.Has(consensus.DeferValidatorStart) && lookups < 4 {
				t.Fatal("normal selected source missing", starts, lookups)
			}
			plan, err := Inspect(t.Context(), prepared, chain, "8282", genesis, 1, 2)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range plan.Heights {
				if row.Status != "complete" {
					t.Fatal("ordered authority became an application gap", row)
				}
			}
			for _, answer := range plan.Answers {
				if answer.Source.Kind == int(inputlog.EnvValidatorsAt) {
					t.Fatal("authority escaped into application answers")
				}
			}
			for _, scope := range []string{"step", "context"} {
				helper := testHelper(t, "core")
				helper.AnswerScope = scope
				steps := 0
				result, err := Execute(t.Context(), plan, helper, func(step Step) error {
					steps++
					if step.Class != "match" {
						t.Error("normal selected replay diverged", step)
					}
					return nil
				})
				if err != nil || steps == 0 || result.Mismatches != 0 || result.Matches != int64(steps) {
					t.Fatal("normal selected trace failed", scope, result, steps, err)
				}
			}
			if !mask.Has(consensus.DeferValidatorStart) {
				return
			}
			// A new detached observer model carries an unavailable reason. Original
			// journal files and signed blocks are never changed or fed back to actors.
			dir := t.TempDir()
			writer, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, identity)
			if err != nil {
				t.Fatal(err)
			}
			restore := &journal.RestoreRec{Version: journal.RestoreSourceVersion, EngineRun: 1, From: "1", Unavailable: "validator_start_profile"}
			writer.Put(journal.Record{Body: restore})
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			input := messages.Input{ID: "unavailable-start-model", Kind: "journal", Node: strings.ToLower(identity.Self.Hex()), Path: dir}
			sum, err := messages.Fingerprint(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			unavailable, err := Inspect(t.Context(), messages.Prepared{Input: input, Summary: sum}, chain, "8282", genesis, 1, 2)
			if err != nil || unavailable.JournalIssue != "validator_start_restore_unavailable" {
				t.Fatal("unsupported restore mislabeled as damage", unavailable.JournalIssue, err)
			}
			for _, row := range unavailable.Heights {
				if row.Status == "complete" {
					t.Fatal("observer model became complete runtime recovery")
				}
			}
			report, err := journal.CheckRestoreSources([]journal.Record{{Body: &journal.SegmentRec{Identity: identity}}, {Body: restore}}, journal.CoreSourceLimits{Records: 16, Runs: 2, Steps: 16, Environments: 32, Outputs: 32, Bytes: 1 << 20})
			if err != nil || report.Status != "unavailable" || report.Reason != "restore_validator_start_profile" {
				t.Fatal("independent source became consistent", report, err)
			}
		})
	}
}

func TestValidatorStartUnsupportedResultRemainsNotComparable(t *testing.T) {
	if code := answerErrorCode(fmt.Errorf("missing key witness: %w", stepdriver.ErrUnsupported)); code != "unsupported_profile" {
		t.Fatal(code)
	}
	source := t.TempDir()
	writeProtocolFixture(t, source)
	input := messages.Input{ID: "journal", Kind: "journal", Path: source}
	sum, err := messages.Fingerprint(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	chain := filepath.Join(t.TempDir(), "chain.rlp")
	writeProtocolChain(t, chain)
	plan := Plan{Input: messages.Prepared{Input: input, Summary: sum}, Chain: chain, ChainSHA: protocolChainSHA(), SourceVersions: []string{strings.Repeat("a", 40)}, Heights: []Height{{Number: "1", Status: "complete", Steps: 1}}, Steps: []Step{{Ordinal: 2, Run: "synthetic-source", Height: "1", Engine: "18446744073709551615", Number: "1", Input: "start", Recorded: "0x" + strings.Repeat("b", 64), Completeness: "complete"}}}
	rows := []Step{}
	result, err := Execute(t.Context(), plan, testHelper(t, "unsupported_profile"), func(row Step) error { rows = append(rows, row); return nil })
	if err == nil || result.Issue != "unsupported_profile" || result.Matches != 0 || result.Mismatches != 0 || result.NotComparable != 1 || len(rows) != 1 || rows[0].Class != "not_comparable" {
		t.Fatal("unsupported source became match or mismatch", result, rows, err)
	}
}

func writeProtocolFixture(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000000.wal"), []byte("synthetic protocol source"), 0600); err != nil {
		t.Fatal(err)
	}
}
func writeProtocolChain(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("synthetic chain fingerprint"), 0600); err != nil {
		t.Fatal(err)
	}
}
func protocolChainSHA() string {
	sum := sha256.Sum256([]byte("synthetic chain fingerprint"))
	return hex.EncodeToString(sum[:])
}

// Each file here is a newly encoded detached observer model. Original normal
// journals remain read-only and no record is fed to a runtime actor.
func TestValidatorStartUnavailableRestoreDoesNotPoisonAnotherRun(t *testing.T) {
	original, chain, genesis := simulationInput(t)
	baseline, err := Inspect(t.Context(), original, chain, "8282", genesis, 1, 2)
	if err != nil || baseline.JournalIssue != "" {
		t.Fatal("original default baseline unavailable", baseline.JournalIssue, err)
	}
	reader, err := journal.OpenReader(nil, original.Input.Path)
	if err != nil {
		t.Fatal(err)
	}
	var identity journal.Identity
	records := []journal.Record{}
	for {
		record, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if segment, ok := record.Body.(*journal.SegmentRec); ok {
			identity = segment.Identity
			continue
		}
		records = append(records, record)
	}
	if identity.Run == "" || len(records) == 0 {
		t.Fatal("original normal source absent")
	}
	for _, selectedFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(selectedFirst), func(t *testing.T) {
			dir := t.TempDir()
			selected := identity
			selected.Run = "selected-unavailable-model"
			selected.Core.Improvements = uint64(consensus.RestartSafety.With(consensus.DeferValidatorStart))
			unavailable := &journal.RestoreRec{Version: journal.RestoreSourceVersion, EngineRun: 1, From: "1", Unavailable: "validator_start_profile"}
			appendRun := func(id journal.Identity, rows []journal.Record) {
				t.Helper()
				writer, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, id)
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows {
					writer.Put(row)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if selectedFirst {
				appendRun(selected, []journal.Record{{Body: unavailable}})
			}
			appendRun(identity, records)
			if !selectedFirst {
				appendRun(selected, []journal.Record{{Body: unavailable}})
			}
			input := messages.Input{ID: "mixed-observer-model", Kind: "journal", Node: strings.ToLower(identity.Self.Hex()), Path: dir}
			sum, err := messages.Fingerprint(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := Inspect(t.Context(), messages.Prepared{Input: input, Summary: sum}, chain, "8282", genesis, 1, 2)
			if err != nil || plan.JournalIssue != "validator_start_restore_unavailable" {
				t.Fatal("missing scoped unavailable summary", plan.JournalIssue, err)
			}
			if len(plan.Steps) == 0 || len(plan.Steps) != len(baseline.Steps) {
				t.Fatal("default original steps changed")
			}
			for index, step := range plan.Steps {
				original := baseline.Steps[index]
				if step.Run != identity.Run || step.Engine != original.Engine || step.Number != original.Number || step.Input != original.Input || step.Recorded != original.Recorded || step.Completeness != original.Completeness || !reflect.DeepEqual(step.Issues, original.Issues) || hasIssue(step.Issues, "validator_start_restore_unavailable") {
					t.Fatal("another run changed original default classification", step, original)
				}
			}
			if !reflect.DeepEqual(plan.Heights, baseline.Heights) {
				t.Fatal("default height classification changed", plan.Heights, baseline.Heights)
			}
		})
	}
}
