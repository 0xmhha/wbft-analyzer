package scenario

import (
	"context"
	"encoding/json"
	"maps"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func recordedTestConfiguration(t *testing.T, directory string, v sim.Validator) *types.Config {
	t.Helper()
	rows, err := journal.ReadAll(nil, filepath.Join(directory, strings.TrimPrefix(strings.ToLower(v.Address().Hex()), "0x")))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if segment, ok := row.Body.(*journal.SegmentRec); ok {
			cfg, err := types.ParseChainConfig(segment.Core.ChainConfig)
			if err != nil {
				t.Fatal(err)
			}
			return cfg
		}
	}
	t.Fatal("actual simulator configuration missing")
	return nil
}

func TestStaticSettingsEvidenceUsesActualSeedJournals(t *testing.T) {
	sc := timingFixture(t)
	sc.Params.EpochLength = 2
	legacy, err := ExecutionHash(sc)
	if err != nil {
		t.Fatal(err)
	}
	sc.Params.RuleActivations = map[types.RuleName]string{types.RejectNumberJump: "18446744073709551616", types.MinimalSealerBitmap: "2", types.StableCandidateSort: "2"}
	sc.Params.AllowedFutureBlockTime = timingNumber(3)
	configured, err := ExecutionHash(sc)
	if err != nil || configured == legacy {
		t.Fatal("chain settings omitted from execution identity", err)
	}
	sc.Nodes[1].Timing = &sim.TimingParams{RequestTimeoutSeconds: timingNumber(4)}
	var got SeedResult
	err = runSeedsWithEvidence(context.Background(), sc, []int64{1}, 1, 3, false, true, func(r SeedResult) error { got = r; return nil })
	if err != nil || got.Status != "complete" || got.Execution == nil || got.Execution.StaticConfiguration == nil || got.Execution.Timing == nil {
		t.Fatal("actual evidence missing", got, err)
	}
	observed := got.Execution.StaticConfiguration
	if len(observed.Configurations) != 4 || len(observed.UnobservedNodes) != 0 {
		t.Fatal("journal coverage missing", observed)
	}
	digests := map[string]bool{}
	for _, row := range observed.Configurations {
		if row.Run == "" || len(row.SHA256) != 64 || row.Segments < 1 || row.Configuration.SourceRulesDigest != "" || row.Configuration.RuleActivations[string(types.RejectNumberJump)] != "18446744073709551616" || row.Configuration.RuleActivations[string(types.MinimalSealerBitmap)] != "2" || row.Configuration.RuleActivations[string(types.StableCandidateSort)] != "2" || row.Configuration.AllowedFutureBlockTime != 3 {
			t.Fatal("requested settings masqueraded as observed settings", row)
		}
		digests[row.RulesDigest] = true
		found := false
		for _, timer := range got.Execution.Timing.Configurations {
			if timer.Node == row.Node && timer.Run == row.Run && timer.EngineRun == row.EngineRun && timer.SHA256 == row.SHA256 {
				found = true
			}
		}
		if !found {
			t.Fatal("timing and settings came from different executions")
		}
	}
	if len(digests) != 2 {
		t.Fatal("per-node parameters incorrectly share a generated digest", digests)
	}
	model := modeledStaticConfiguration(sc)
	model.RuleActivations[string(types.RejectNumberJump)] = "999"
	if sc.Params.RuleActivations[types.RejectNumberJump] != "18446744073709551616" {
		t.Fatal("display aliases executable settings")
	}
	directory := t.TempDir()
	result, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: directory})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Violations) != 0 {
		t.Fatal(result.Violations)
	}
	for _, head := range result.Heads {
		if head < sc.Until.Height {
			t.Fatal("configured simulator nodes did not reach the stop height", result.Heads)
		}
	}
	for _, n := range []int{2, 4, 6, 8} {
		if len(result.Chain) <= n {
			t.Fatal("configured epoch block missing", n)
		}
		x, err := codec.DecodeExtra(result.Chain[n].Header)
		if err != nil || x.EpochInfo == nil || len(x.EpochInfo.Validators) != 4 {
			t.Fatalf("configured epoch block %d: %+v %v", n, x, err)
		}
	}
	for _, v := range sc.Validators {
		cfg := recordedTestConfiguration(t, directory, v)
		if cfg.Base().EpochLength != 2 || cfg.Rules(types.StableCandidateSort, types.HeightFromUint64(1)) || !cfg.Rules(types.StableCandidateSort, types.HeightFromUint64(2)) {
			t.Fatal("actual journal lost the configured epoch or activation boundary")
		}
	}
	sc.Params.RuleActivations[types.RejectNumberJump] = "0"
	if _, err := observedStaticConfiguration(context.Background(), sc, result, directory); err == nil {
		t.Fatal("different actual activation accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observedStaticConfiguration(ctx, sc, result, directory); err == nil {
		t.Fatal("canceled observation accepted")
	}
}

func TestConfiguredMessageSelectionKeepsPartialEvidenceAcrossSeeds(t *testing.T) {
	sc := timingFixture(t)
	sc.Params.RuleActivations = map[types.RuleName]string{types.RejectNumberJump: "0"}
	sc.MessageChanges = []sim.MessageDeliveryChange{{Kind: sim.MessageDrop, First: sim.MessageSelector{Peer: sc.Validators[0].Address(), Receiver: sc.Validators[1].Address(), Signer: sc.Validators[2].Address(), Code: codec.CodePrepare, Sequence: "999", Round: "0", Occurrence: 1}}}
	count := 0
	err := RunSeeds(context.Background(), sc, []int64{1, 2}, 1, 3, func(r SeedResult) error {
		count++
		if r.Status != "partial" || len(r.Heights) != 3 || r.Execution.Messages == nil || r.Execution.Messages.Changes[0].Status != "unmatched" || r.Execution.StaticConfiguration == nil || len(r.Execution.StaticConfiguration.Configurations) != 4 {
			t.Fatal("message failure erased settings or actual partial outcome", r)
		}
		return nil
	})
	if err != nil || count != 2 {
		t.Fatal("partial seed stopped later seeds", count, err)
	}
}

func TestDefaultStaticSettingsDoNotChangeLegacyJSON(t *testing.T) {
	for _, value := range []any{Experiment{}, SeedExecution{}} {
		data, err := json.Marshal(value)
		if err != nil || strings.Contains(string(data), "static_configuration") {
			t.Fatal("default evidence changed historical JSON", string(data), err)
		}
	}
	if modeledStaticConfiguration(timingFixture(t)) != nil {
		t.Fatal("default model gained synthetic settings")
	}
}

func TestStaticSettingsJournalCoverageKeepsRestartWriters(t *testing.T) {
	sc := timingFixture(t)
	sc.Params.AllowedFutureBlockTime = timingNumber(3)
	sc.Schedule = []sim.NodeEvent{{At: 2500 * time.Millisecond, Node: sc.Validators[0].Address(), Action: sim.ActionStop}, {At: 3 * time.Second, Node: sc.Validators[0].Address(), Action: sim.ActionRestart}}
	var got SeedResult
	err := runSeeds(context.Background(), sc, []int64{1}, 1, 3, true, func(r SeedResult) error { got = r; return nil })
	if err != nil || got.Execution == nil || got.Execution.StaticConfiguration == nil {
		t.Fatal(got, err)
	}
	observed := got.Execution.StaticConfiguration
	if len(observed.UnobservedNodes) != 0 {
		t.Fatal("started node lost configuration evidence", observed)
	}
	writers := map[string]bool{}
	for _, row := range observed.Configurations {
		if row.Configuration.AllowedFutureBlockTime != 3 {
			t.Fatal("configuration lost across restart", row)
		}
		if row.Node == 0 {
			writers[row.Run] = true
		}
	}
	if len(writers) != 2 {
		t.Fatal("restart writer configurations collapsed", observed)
	}
}

func TestStaticSettingsSurviveCompleteFittingAndExperimentStorageBoundary(t *testing.T) {
	o := empiricalFitFixtureWithSettings(t, sim.Epoch, map[types.RuleName]string{types.RejectNumberJump: "18446744073709551616"}, timingNumber(3))
	fit, err := Fit(context.Background(), o)
	if err != nil || fit.Model.Status != "complete" || fit.Scenario == nil || fit.StaticConfiguration == nil {
		t.Fatal("configured source not fitted", fit.Model, err)
	}
	var started Experiment
	var records []SeedRecord
	change := NetworkChange{Kind: "set_timing", ToNS: int64(o.Until), Timing: &TimingChange{Nodes: []NodeTimingChange{{Node: indexPointer(1), Values: TimingValues{RequestTimeoutSeconds: timingNumber(3)}}}}}
	result, err := ExecuteExperimentWithRecorded(context.Background(), *fit.Scenario, fit.Provenance, fit.Model, []RoundCount{{Total: 3}}, fit.Recorded, change, o.From, o.To, func(e Experiment) error { started = e; return nil }, func(r SeedRecord) error { records = append(records, r); return nil })
	if err != nil || result.Status != "completed" || result.StaticConfiguration == nil || started.StaticConfiguration == nil || len(records) != 4 {
		t.Fatal("configuration lost before persistence", result, err)
	}
	for _, e := range []Experiment{started, result} {
		if e.StaticConfiguration.SourceRulesDigest != "" || e.StaticConfiguration.AllowedFutureBlockTime != 3 || e.StaticConfiguration.RuleActivations[string(types.RejectNumberJump)] != "18446744073709551616" {
			t.Fatal("modeled and source settings conflated", e.StaticConfiguration)
		}
	}
	for _, record := range records {
		if record.Result.Execution == nil || record.Result.Execution.StaticConfiguration == nil || len(record.Result.Execution.StaticConfiguration.Configurations) != 4 {
			t.Fatal("baseline or counterfactual actual configuration absent", record)
		}
	}
}

func TestRecordedStaticChainSettingsReachOfficialSimulator(t *testing.T) {
	for _, test := range []struct {
		name   string
		rules  map[types.RuleName]string
		future *uint64
	}{
		{name: "default"},
		{name: "active_zero", rules: map[types.RuleName]string{types.RejectNumberJump: "0"}},
		{name: "full_activation_and_future", rules: map[types.RuleName]string{types.RejectNumberJump: "18446744073709551616"}, future: timingNumber(3)},
		{name: "future_only", future: timingNumber(3)},
		{name: "explicit_zero_normalizes_default", future: timingNumber(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := timingFixture(t)
			source.Params.RuleActivations = test.rules
			source.Params.AllowedFutureBlockTime = test.future
			directory := t.TempDir()
			result, err := sim.Run(context.Background(), source, sim.Output{JournalDir: directory})
			if err != nil {
				t.Fatal(err)
			}
			cfg := recordedTestConfiguration(t, directory, source.Validators[0])
			facts, err := InspectChain(result.Chain, cfg, 1, 7)
			if err != nil {
				t.Fatal(err)
			}
			wantFuture := uint64(0)
			if test.future != nil {
				wantFuture = *test.future
			}
			if !maps.Equal(facts.Params.RuleActivations, test.rules) {
				t.Fatal("source activations lost", facts.Params.RuleActivations)
			}
			if wantFuture == 0 && facts.Params.AllowedFutureBlockTime != nil || wantFuture > 0 && (facts.Params.AllowedFutureBlockTime == nil || *facts.Params.AllowedFutureBlockTime != wantFuture) {
				t.Fatal("source future allowance lost or default identity changed")
			}
			if len(test.rules) == 0 && wantFuture == 0 {
				if facts.StaticConfiguration != nil {
					t.Fatal("default metadata changed historical reports")
				}
			} else {
				if facts.StaticConfiguration == nil || facts.StaticConfiguration.SourceRulesDigest != cfg.RulesDigest().Hex() || facts.StaticConfiguration.AllowedFutureBlockTime != wantFuture {
					t.Fatal("recorded configuration evidence missing", facts.StaticConfiguration)
				}
			}
			nodes, links := completeFixture()
			modeled, err := Build(nodes, links, facts.Params, []time.Duration{time.Millisecond}, []time.Duration{time.Millisecond}, source.Until)
			if err != nil {
				t.Fatal(err)
			}
			modeled.Nodes[1].Timing = &sim.TimingParams{RequestTimeoutSeconds: timingNumber(3)}
			destination := t.TempDir()
			if _, err := sim.Run(context.Background(), modeled, sim.Output{JournalDir: destination}); err != nil {
				t.Fatal(err)
			}
			for _, v := range modeled.Validators {
				actual := recordedTestConfiguration(t, destination, v)
				if !maps.Equal(actual.RuleActivations(), test.rules) || actual.ConfigAt(types.HeightFromUint64(1)).AllowedFutureBlockTime != wantFuture {
					t.Fatal("executable journal differs from recorded settings")
				}
			}
			if facts.StaticConfiguration != nil && len(test.rules) > 0 {
				facts.StaticConfiguration.RuleActivations[string(types.RejectNumberJump)] = "999"
				if facts.Params.RuleActivations[types.RejectNumberJump] != test.rules[types.RejectNumberJump] {
					t.Fatal("display metadata aliases executable configuration")
				}
			}
		})
	}
}
