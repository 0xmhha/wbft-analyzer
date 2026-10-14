package scenario

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

func TestOfficialSimulatorSeedOutputs(t *testing.T) {
	keys, err := TestValidators([]types.Address{{19: 3}, {19: 1}, {19: 4}, {19: 2}})
	if err != nil {
		t.Fatal(err)
	}
	sc := sim.Scenario{Validators: keys, Until: sim.Stop{Height: 3, Duration: time.Minute}}
	collect := func() []SeedResult {
		out := []SeedResult{}
		err := RunSeeds(context.Background(), sc, []int64{1, 2}, 1, 3, func(r SeedResult) error { out = append(out, r); return nil })
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	got := collect()
	if len(got) != 2 || got[0].Status != "complete" || len(got[0].Heights) != 3 {
		t.Fatalf("run %+v", got)
	}
	if !reflect.DeepEqual(got, collect()) {
		t.Fatal("seed outputs changed")
	}
	sc.Until = sim.Stop{Height: 1, Duration: time.Second}
	err = RunSeeds(context.Background(), sc, []int64{1}, 1, 3, func(r SeedResult) error {
		if r.Status != "partial" {
			t.Fatal("unfinished run marked complete")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop")
	if err := RunSeeds(context.Background(), sc, []int64{1}, 1, 3, func(SeedResult) error { return stop }); !errors.Is(err, stop) {
		t.Fatal("emit error ignored")
	}
	if err := RunSeeds(context.Background(), sc, []int64{1, 1}, 1, 3, func(SeedResult) error { return nil }); err == nil {
		t.Fatal("duplicate seed accepted")
	}
}
