package scenario

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
)

func TestTimingObservationsRetainActualConfigurationsDeadlinesAndRestart(t *testing.T) {
	sc := timingFixture(t)
	change := NetworkChange{Kind: "set_timing", ToNS: int64(time.Minute), Timing: &TimingChange{Global: &TimingValues{RequestTimeoutSeconds: timingNumber(5), BlockPeriodSeconds: timingNumber(2), MaxRequestTimeoutSeconds: timingNumber(17)}, Nodes: []NodeTimingChange{{Node: indexPointer(1), Values: TimingValues{RequestTimeoutSeconds: timingNumber(7), MaxRequestTimeoutSeconds: timingNumber(0)}}}}}
	changed, _, err := ApplyNetworkChange(sc, change)
	if err != nil {
		t.Fatal(err)
	}
	changed.Schedule = []sim.NodeEvent{{Node: changed.Validators[1].Address(), At: 5 * time.Second, Action: sim.ActionStop}, {Node: changed.Validators[1].Address(), At: 7 * time.Second, Action: sim.ActionRestart}}
	effect, err := TimingChangeEvidence(sc, change)
	if err != nil || effect.Nodes[1].Before.RequestTimeoutMS != 2000 || effect.Nodes[1].After.RequestTimeoutMS != 7000 || effect.Nodes[1].After.MaxRequestTimeoutSeconds != 0 || effect.Nodes[0].After.BlockPeriodSeconds != 2 {
		t.Fatal("resolved settings do not distinguish scope and inheritance", effect, err)
	}
	var plain, observed SeedResult
	if err := runSeeds(context.Background(), changed, []int64{7}, 1, 8, false, func(r SeedResult) error { plain = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := runSeedsWithEvidence(context.Background(), changed, []int64{7}, 1, 8, true, true, func(r SeedResult) error { observed = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if plain.Execution.Timing != nil || plain.Execution.Lifecycle != nil || observed.Execution.Timing == nil || observed.Execution.Lifecycle == nil {
		t.Fatal("observations missing or backfilled into ordinary seed results")
	}
	actual := observed.Execution.Timing
	observed.Execution.Timing, observed.Execution.Lifecycle = nil, nil
	if !reflect.DeepEqual(observed, plain) {
		t.Fatal("retaining timing evidence changed execution outcomes")
	}
	runs := map[string]bool{}
	for _, cfg := range actual.Configurations {
		if cfg.Segments < 1 || len(cfg.SHA256) != 64 || cfg.Parameters.BlockPeriodSeconds != 2 {
			t.Fatal("journal evidence incomplete", cfg)
		}
		if cfg.Node == 1 {
			runs[cfg.Run] = true
			if cfg.Parameters.RequestTimeoutMS != 7000 || cfg.Parameters.MaxRequestTimeoutSeconds != 0 {
				t.Fatal("restart journal used global settings", cfg)
			}
		} else if cfg.Parameters.RequestTimeoutMS != 5000 || cfg.Parameters.MaxRequestTimeoutSeconds != 17 {
			t.Fatal("global journal settings differ", cfg)
		}
	}
	if len(runs) != 2 {
		t.Fatal("both actual node incarnations were not observed", runs)
	}
	initial, restarted := map[int]int64{}, false
	for _, arm := range actual.Arms {
		if arm.DeadlineNS != nil && *arm.DeadlineNS-arm.AtNS != arm.DurationMS*int64(time.Millisecond) {
			t.Fatal("observed timer deadline is wrong", arm)
		}
		if arm.Round == "0" {
			if _, found := initial[arm.Node]; !found {
				initial[arm.Node] = arm.DurationMS
			}
		}
		if arm.Node == 1 && arm.AtNS >= int64(7*time.Second) {
			restarted = true
		}
	}
	if !reflect.DeepEqual(initial, map[int]int64{0: 5000, 1: 7000, 2: 5000, 3: 5000}) || !restarted {
		t.Fatal("actual per-node timers or restart were not retained", initial, restarted)
	}
	for _, coverage := range actual.Coverage {
		if coverage.Total < uint64(coverage.Retained) || coverage.Retained > timingArmsPerNode {
			t.Fatal("timer sampling count is inconsistent", coverage)
		}
	}
}

func TestTimingObservationSampleRetainsFirstAndLastInAnyInputOrder(t *testing.T) {
	var forward, reverse []SeedTimerArm
	for i := 0; i < 100; i++ {
		forward = retainTimingArm(forward, SeedTimerArm{AtNS: int64(i)})
		reverse = retainTimingArm(reverse, SeedTimerArm{AtNS: int64(99 - i)})
	}
	if !reflect.DeepEqual(forward, reverse) || len(forward) != 32 {
		t.Fatal("sampling depends on file or map order")
	}
	for i, row := range forward {
		want := i
		if i >= 16 {
			want += 68
		}
		if row.AtNS != int64(want) {
			t.Fatal("middle sample retained while first/last was omitted", i, row)
		}
	}
}

func TestTimingObservationsRejectJournalsFromDifferentConfiguration(t *testing.T) {
	sc := timingFixture(t)
	sc.Seed = 7
	dir := t.TempDir()
	result, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observedTiming(sc, result, dir); err != nil {
		t.Fatal("valid exported journal rejected", err)
	}
	sc.Nodes = append([]sim.NodeSpec(nil), sc.Nodes...)
	sc.Nodes[0].Timing = &sim.TimingParams{RequestTimeoutSeconds: timingNumber(9)}
	if _, err := observedTiming(sc, result, dir); err == nil {
		t.Fatal("requested settings substituted for actual journal configuration")
	}
}
