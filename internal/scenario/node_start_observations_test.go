package scenario

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestObservedNodeStartsPreserveOutcomesAndDoNotInventUnreachedRequests(t *testing.T) {
	sc := delayFixture(t)
	sc.Seed = 7
	change := lifecycleChange("merge", 0, int64(time.Minute), lifecycleCommand(3, int64(2*time.Second), "stop"), lifecycleCommand(3, int64(4*time.Second), "restart"))
	changed, _, err := ApplyNetworkChange(sc, change)
	if err != nil {
		t.Fatal(err)
	}
	var without, with SeedResult
	if err := runSeeds(context.Background(), changed, []int64{7}, 1, 8, false, func(r SeedResult) error { without = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := runSeeds(context.Background(), changed, []int64{7}, 1, 8, true, func(r SeedResult) error { with = r; return nil }); err != nil {
		t.Fatal(err)
	}
	observations := with.Execution.Lifecycle
	if observations == nil || observations.Source != "official_simulator_node_start_events/1" {
		t.Fatal("observations unavailable")
	}
	found := false
	for _, start := range observations.Starts {
		if start.Node == 3 && start.AtNS >= int64(4*time.Second) && start.Status == "started" && start.WALRecords != nil && *start.WALRecords > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("real restart and WAL recovery were not observed", observations)
	}
	with.Execution.Lifecycle = nil
	if !reflect.DeepEqual(with, without) {
		t.Fatal("observing starts changed simulator outputs")
	}
	later := lifecycleChange("merge", 0, int64(time.Minute), lifecycleCommand(3, int64(50*time.Second), "stop"), lifecycleCommand(3, int64(55*time.Second), "restart"))
	changed, _, err = ApplyNetworkChange(sc, later)
	if err != nil {
		t.Fatal(err)
	}
	if err := runSeeds(context.Background(), changed, []int64{7}, 1, 8, true, func(r SeedResult) error {
		if r.SimulationNS >= int64(50*time.Second) {
			t.Fatal("fixture did not stop before future commands")
		}
		for _, start := range r.Execution.Lifecycle.Starts {
			if start.AtNS >= int64(50*time.Second) {
				t.Fatal("unreached request invented a start", start)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
