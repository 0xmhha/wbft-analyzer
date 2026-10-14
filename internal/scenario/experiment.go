package scenario

import (
	"context"
	"errors"

	"github.com/0xmhha/wbft/conformance/sim"
)

const ExperimentVersion = "wbft-network-experiment/1"

type Experiment struct {
	ExecutionSHA256 string           `json:"execution_sha256"`
	From            uint64           `json:"from,string"`
	To              uint64           `json:"to,string"`
	RecordedHeights []Height         `json:"recorded_heights"`
	RecordedSHA256  string           `json:"recorded_sha256"`
	RecordedCounts  []RoundCount     `json:"recorded_counts"`
	Version         string           `json:"version"`
	Status          string           `json:"status"`
	Provenance      Provenance       `json:"provenance"`
	SourceSHA256    string           `json:"source_sha256"`
	Change          CutOutgoing      `json:"change"`
	ChangeSHA256    string           `json:"change_sha256"`
	Model           Assessment       `json:"model"`
	Baseline        *RoundComparison `json:"baseline_rounds"`
	TimeCheck       string           `json:"baseline_time_check"`
	BaselineSeeds   []SeedResult     `json:"-"`
	ChangedSeeds    []SeedResult     `json:"-"`
}

type SeedRecord struct {
	Mode   string     `json:"mode"`
	Result SeedResult `json:"result"`
}

// ExecuteExperiment preserves model and baseline failures as distinct facts.
// A completed execution never by itself establishes baseline reproducibility.
func ExecuteExperiment(ctx context.Context, sc sim.Scenario, provenance Provenance, model Assessment, recorded []RoundCount, change CutOutgoing, from, to uint64, emit func(SeedRecord) error) (Experiment, error) {
	return ExecuteExperimentWithBegin(ctx, sc, provenance, model, recorded, change, from, to, nil, emit)
}

func ExecuteExperimentWithBegin(ctx context.Context, sc sim.Scenario, provenance Provenance, model Assessment, recorded []RoundCount, change CutOutgoing, from, to uint64, begin func(Experiment) error, emit func(SeedRecord) error) (Experiment, error) {

	return ExecuteExperimentWithRecorded(ctx, sc, provenance, model, recorded, nil, change, from, to, begin, emit)
}

func ExecuteExperimentWithRecorded(ctx context.Context, sc sim.Scenario, provenance Provenance, model Assessment, recorded []RoundCount, heights []Height, change CutOutgoing, from, to uint64, begin func(Experiment) error, emit func(SeedRecord) error) (Experiment, error) {

	out := Experiment{From: from, To: to, RecordedCounts: append([]RoundCount(nil), recorded...), RecordedHeights: append([]Height{}, heights...), Version: ExperimentVersion, Status: "running", Model: model, Change: change, TimeCheck: "threshold_unconfigured", BaselineSeeds: []SeedResult{}, ChangedSeeds: []SeedResult{}}
	if err := ValidateRecorded(out.RecordedHeights, recorded, from, to); err != nil {
		out.Status = "failed"
		return out, err
	}
	out.RecordedSHA256 = RecordedHash(out.RecordedHeights)
	fixed, sourceHash, err := SealProvenance(provenance)
	if err != nil {
		out.Status = "failed"
		return out, err
	}
	out.Provenance = fixed
	out.SourceSHA256 = sourceHash
	changed, changeHash, err := ApplyCutOutgoing(sc, change)
	if err != nil {
		out.Status = "failed"
		return out, err
	}
	out.ChangeSHA256 = changeHash
	out.ExecutionSHA256, err = ExecutionHash(sc)
	if err != nil {
		out.Status = "failed"
		return out, err
	}
	if len(sc.Adversaries) > 0 || len(sc.Faults) > 0 || len(sc.Disk) > 0 || len(sc.App.BadProposals) > 0 || len(sc.App.FailedImports) > 0 {
		out.Status = "failed"
		return out, errors.New("unsupported network experiment behavior")
	}
	if _, err := RunHomogeneity(recorded); err != nil {
		out.Status = "failed"
		return out, err
	}
	if model.Version != FitVersion || model.Status != "complete" && model.Status != "partial" {
		out.Status = "failed"
		return out, errors.New("invalid fitting assessment")
	}
	if begin != nil {
		if err := begin(out); err != nil {
			out.Status = "failed"
			return out, err
		}
	}
	run := func(mode string, s sim.Scenario, target *[]SeedResult) error {
		return RunSeeds(ctx, s, fixed.Seeds, from, to, func(r SeedResult) error {
			if err := emit(SeedRecord{Mode: mode, Result: r}); err != nil {
				return err
			}
			*target = append(*target, r)
			return nil
		})
	}
	if err := run("baseline", sc, &out.BaselineSeeds); err != nil {
		out.Status = "partial"
		return out, err
	}
	counts := []RoundCount{}
	for _, r := range out.BaselineSeeds {
		if r.Status != "complete" {
			out.Status = "partial"
			return out, errors.New("baseline seed execution incomplete")
		}
		c := RoundCount{Total: int64(len(r.Heights))}
		for _, h := range r.Heights {
			if h.Round > 0 {
				c.Late++
			}
		}
		counts = append(counts, c)
	}
	comparison, err := CompareRounds(recorded, counts, 1)
	if err != nil {
		out.Status = "partial"
		return out, err
	}
	out.Baseline = &comparison
	// Even a failed baseline is retained with the counterfactual outputs.
	if err := run("counterfactual", changed, &out.ChangedSeeds); err != nil {
		out.Status = "partial"
		return out, err
	}
	out.Status = "completed"
	for _, r := range out.ChangedSeeds {
		if r.Status != "complete" {
			out.Status = "partial"
		}
	}
	return out, nil
}

// Credibility describes evidence strength independently of execution status.
func (e Experiment) Credibility() string {
	if e.Status != "completed" {
		return "execution_incomplete"
	}
	if e.Model.Status != "complete" {
		return "model_incomplete"
	}
	if e.Baseline == nil || e.Baseline.Status != "not_distinguishable" {
		return "baseline_rounds_unproved"
	}
	if e.TimeCheck != "passed" {
		return "baseline_time_unproved"
	}
	return "baseline_reproduced"
}
