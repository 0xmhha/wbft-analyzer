// Package scenariojob persists independently seeded network experiments.
package scenariojob

import (
	"context"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/conformance/sim"
)

type Options struct {
	JobID           int64
	JobOwner        string
	OnSeedStored    func(scenario.SeedRecord) error
	Scenario        sim.Scenario
	Provenance      scenario.Provenance
	Model           scenario.Assessment
	RecordedHeights []scenario.Height
	Recorded        []scenario.RoundCount
	Change          scenario.NetworkChange
	From, To        uint64
}

type Result struct {
	ID      int64               `json:"id"`
	Summary scenario.Experiment `json:"summary"`
}

// Run fences dataset deletion for the entire experiment and preserves saved
// seed prefixes on cancellation or execution failure. Source fitting occurs
// before this entry point from retained immutable snapshots.
func Run(ctx context.Context, s *store.Store, o Options) (Result, error) {
	if o.Provenance.CoreCommit != reexec.LinkedCommit() || reexec.LinkedCommit() == "unknown" {
		return Result{}, errors.New("scenario simulator version unavailable or mismatched")
	}
	return run(ctx, s, o)
}

// run is the storage execution layer after the runtime version fence.
func run(ctx context.Context, s *store.Store, o Options) (Result, error) {
	out := Result{}
	release, err := s.DatasetReadLease(ctx, o.Provenance.Dataset)
	if err != nil {
		return out, err
	}
	defer release()
	final, runErr := scenario.ExecuteExperimentWithRecorded(ctx, o.Scenario, o.Provenance, o.Model, o.Recorded, o.RecordedHeights, o.Change, o.From, o.To, func(initial scenario.Experiment) error {
		var id int64
		var err error
		if o.JobID > 0 {
			id, err = s.BeginScenarioJob(ctx, o.JobID, o.JobOwner, initial)
		} else {
			id, err = s.BeginScenario(ctx, initial)
		}
		out.ID = id
		return err
	}, func(seed scenario.SeedRecord) error {
		if err := s.PutScenarioSeed(ctx, out.ID, seed); err != nil {
			return err
		}
		if o.OnSeedStored != nil {
			return o.OnSeedStored(seed)
		}
		return nil
	})
	out.Summary = final
	if out.ID == 0 {
		return out, runErr
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.FinishScenario(cleanup, out.ID, final); err != nil {
		return out, errors.Join(runErr, err)
	}
	stored, err := s.ScenarioRun(cleanup, o.Provenance.Dataset, out.ID)
	if err != nil {
		return out, errors.Join(runErr, err)
	}
	out.Summary = stored
	return out, runErr
}
