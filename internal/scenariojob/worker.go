package scenariojob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

var ErrSource = errors.New("network scenario source unavailable")
var ErrChange = errors.New("network change outside registered model")

type SourceSpec struct {
	ProcessingPolicy  string              `json:"processing_policy,omitempty"`
	ProcessingWorkers int                 `json:"processing_workers,omitempty"`
	TransportManifest string              `json:"transport_manifest,omitempty"`
	Model             string              `json:"model,omitempty"`
	RuntimeManifest   string              `json:"runtime_manifest,omitempty"`
	WireMetric        string              `json:"wire_metric,omitempty"`
	TransportInputs   []string            `json:"transport_inputs,omitempty"`
	ID                string              `json:"id"`
	Dataset           int64               `json:"dataset"`
	Chain             string              `json:"chain"`
	Events            string              `json:"events_manifest"`
	Origin            string              `json:"origin"`
	From              uint64              `json:"from"`
	To                uint64              `json:"to"`
	Duration          string              `json:"duration"`
	Clock             string              `json:"clock"`
	SkewMS            int64               `json:"skew_ms"`
	Seeds             int                 `json:"seeds"`
	Runtime           []scenario.Node     `json:"runtime"`
	Coverage          []scenario.Coverage `json:"coverage"`
}

type EpochInfo struct {
	Block                string   `json:"block"`
	Candidates           []string `json:"candidates"`
	Validators           []string `json:"validators"`
	HeaderInputsVerified bool     `json:"header_inputs_verified"`
}

func publicEpochs(epochs []scenario.RecordedEpoch) []EpochInfo {
	out := []EpochInfo{}
	for _, e := range epochs {
		x := EpochInfo{Block: strconv.FormatUint(e.Block, 10), Candidates: []string{}, Validators: []string{}, HeaderInputsVerified: e.HeaderInputsVerified}
		for _, a := range e.Candidates {
			x.Candidates = append(x.Candidates, a.Hex())
		}
		for _, a := range e.Validators {
			x.Validators = append(x.Validators, a.Hex())
		}
		out = append(out, x)
	}
	return out
}

type SourceInfo struct {
	WallOrigin          string                        `json:"wall_origin"`
	TransportScope      *scenario.TransportScope      `json:"transport_scope,omitempty"`
	Mode                string                        `json:"mode"`
	DeclaredModel       scenario.Assessment           `json:"declared_runtime_model"`
	Empirical           *scenario.EmpiricalProjection `json:"empirical,omitempty"`
	ApplicationPolicies []scenario.ApplicationPolicy  `json:"application_policies"`
	RuntimeObservations []scenario.RuntimeBinding     `json:"runtime_observations"`
	WireMetric          string                        `json:"wire_metric"`
	TransportInputs     []scenario.Input              `json:"transport_inputs"`
	Epochs              []EpochInfo                   `json:"epochs"`
	Scope               scenario.ScopeCounts          `json:"scope"`
	Nodes               []string                      `json:"nodes"`
	DurationNS          int64                         `json:"duration_ns"`
	ID                  string                        `json:"id"`
	Dataset             int64                         `json:"dataset_id"`
	From                string                        `json:"from"`
	To                  string                        `json:"to"`
	SourceSHA           string                        `json:"source_sha256"`
	ExecutionSHA        string                        `json:"execution_sha256"`
	Status              string                        `json:"status"`
	Model               scenario.Assessment           `json:"model"`
}

type registered struct {
	request   FitRequest
	info      SourceInfo
	network   int64
	nodes     int
	duration  time.Duration
	delays    map[[2]int]time.Duration
	lifecycle scenario.LifecycleScope
}
type Worker struct {
	store   *store.Store
	sources map[string]registered
	order   []string
}

// NewEmpty exposes no registered source and cannot claim an execution.
func NewEmpty(s *store.Store) *Worker {
	return &Worker{store: s, sources: map[string]registered{}, order: []string{}}
}

func Load(ctx context.Context, s *store.Store, path string) (*Worker, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 256<<10 {
		return nil, ErrSource
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 256<<10 {
		return nil, ErrSource
	}
	var specs []SourceSpec
	if whatif.DecodeJSON(raw, &specs) != nil || len(specs) == 0 || len(specs) > 16 {
		return nil, ErrSource
	}
	w := NewEmpty(s)
	for _, spec := range specs {
		if !scenario.ValidModel(spec.Model) || !scenario.ValidProcessing(spec.ProcessingPolicy, spec.ProcessingWorkers) || spec.ProcessingPolicy != "" && spec.Model != scenario.EmpiricalCoreModel || !logs.Identifier(spec.ID) || spec.Dataset < 1 || spec.From < 1 || spec.To < spec.From || spec.To-spec.From >= 10000 || spec.Seeds < 2 || spec.Seeds > 128 || spec.SkewMS < 0 || spec.SkewMS > 3600000 || spec.Clock != "shared-host" && spec.Clock != "ntp" && spec.Clock != "unknown" {
			return nil, ErrSource
		}
		if _, ok := w.sources[spec.ID]; ok {
			return nil, ErrSource
		}
		origin, err := time.Parse(time.RFC3339Nano, spec.Origin)
		if err != nil {
			return nil, ErrSource
		}
		duration, err := time.ParseDuration(spec.Duration)
		if err != nil || duration <= 0 || duration > 24*time.Hour {
			return nil, ErrSource
		}
		seeds := make([]int64, spec.Seeds)
		for i := range seeds {
			seeds[i] = int64(i + 1)
		}
		if !filepath.IsAbs(spec.Chain) {
			spec.Chain = filepath.Join(filepath.Dir(path), spec.Chain)
		}
		if spec.Events != "" && !filepath.IsAbs(spec.Events) {
			spec.Events = filepath.Join(filepath.Dir(path), spec.Events)
		}
		if spec.TransportManifest != "" && !filepath.IsAbs(spec.TransportManifest) {
			spec.TransportManifest = filepath.Join(filepath.Dir(path), spec.TransportManifest)
		}
		request := FitRequest{TransportManifest: spec.TransportManifest, RuntimeManifest: spec.RuntimeManifest, ChainPath: spec.Chain, EventManifest: spec.Events, Options: scenario.FitOptions{ProcessingPolicy: spec.ProcessingPolicy, ProcessingWorkers: spec.ProcessingWorkers, Model: spec.Model, WireMetric: spec.WireMetric, TransportInputs: spec.TransportInputs, Dataset: spec.Dataset, From: spec.From, To: spec.To, Origin: origin, Until: duration, Clock: pairs.Clock{Model: spec.Clock, SkewMS: spec.SkewMS}, Seeds: seeds, Runtime: spec.Runtime, Coverage: spec.Coverage}}
		raw, err := json.Marshal(spec)
		if err != nil {
			return nil, ErrSource
		}
		digest := sha256.Sum256(raw)
		declaration := hex.EncodeToString(digest[:])
		saved, err := s.ScenarioSource(ctx, spec.Dataset, spec.ID)
		if err == nil {
			if saved.DeclarationSHA != declaration {
				return nil, ErrSource
			}
			request.Snapshot = &saved.Snapshot
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		fitted, snapshot, err := PrepareDataset(ctx, s, request)
		if err != nil {
			return nil, ErrSource
		}
		dataset, _, err := s.ReexecDataset(ctx, spec.Dataset)
		if err != nil {
			return nil, err
		}
		public := SourceInfo{WallOrigin: fitted.WallOrigin, TransportScope: fitted.TransportScope, Mode: fitted.Mode, DeclaredModel: fitted.DeclaredModel, Empirical: fitted.Empirical, ApplicationPolicies: fitted.App.Policies, RuntimeObservations: fitted.RuntimeObservations, WireMetric: fitted.WireMetric, TransportInputs: fitted.TransportInputs, Epochs: publicEpochs(fitted.Epochs), Scope: fitted.Scope, Nodes: []string{}, DurationNS: int64(duration), ID: spec.ID, Dataset: spec.Dataset, From: strconv.FormatUint(spec.From, 10), To: strconv.FormatUint(spec.To, 10), SourceSHA: fitted.SourceSHA256, Status: fitted.Model.Status, Model: fitted.Model}
		for _, node := range fitted.NodeOptions {
			public.Nodes = append(public.Nodes, node.Address.Hex())
		}
		var delayBounds map[[2]int]time.Duration
		var lifecycleBounds scenario.LifecycleScope
		if fitted.Scenario != nil {
			lifecycleBounds, err = scenario.NodeLifecycleBounds(*fitted.Scenario)
			if err != nil {
				return nil, ErrSource
			}
			delayBounds, err = scenario.LinkDelayBounds(*fitted.Scenario)
			if err != nil {
				return nil, ErrSource
			}
			public.ExecutionSHA, err = scenario.ExecutionHash(*fitted.Scenario)
			if err != nil {
				return nil, err
			}
		}
		if err := s.PutScenarioSource(ctx, store.ScenarioSource{Dataset: spec.Dataset, ID: spec.ID, DeclarationSHA: declaration, SourceSHA: fitted.SourceSHA256, ExecutionSHA: public.ExecutionSHA, Snapshot: snapshot}); err != nil {
			return nil, err
		}
		request.Snapshot = &snapshot
		w.sources[spec.ID] = registered{lifecycle: lifecycleBounds, delays: delayBounds, request: request, info: public, network: dataset.NetworkID, nodes: len(fitted.NodeOptions), duration: duration}
		w.order = append(w.order, spec.ID)
	}
	return w, nil
}

func (w *Worker) Sources(network, dataset int64) []SourceInfo {
	out := []SourceInfo{}
	for _, id := range w.order {
		s := w.sources[id]
		if s.network == network && s.info.Dataset == dataset {
			out = append(out, s.info)
		}
	}
	return out
}
func (w *Worker) Enqueue(ctx context.Context, network, dataset int64, id string, change scenario.NetworkChange) (store.ScenarioJob, error) {
	s, ok := w.sources[id]
	if !ok || s.network != network || s.info.Dataset != dataset || s.info.Status != "complete" || s.info.ExecutionSHA == "" {
		return store.ScenarioJob{}, ErrSource
	}
	if err := change.ValidateFor(s.nodes, s.duration); err != nil {
		return store.ScenarioJob{}, ErrChange
	}
	if err := change.ValidateDelayBounds(s.delays); err != nil {
		return store.ScenarioJob{}, ErrChange
	}
	if err := change.ValidateLifecycleBounds(s.lifecycle); err != nil {
		return store.ScenarioJob{}, ErrChange
	}
	return w.store.EnqueueScenario(ctx, store.ScenarioJob{Dataset: dataset, Source: id, SourceSHA: s.info.SourceSHA, ExecutionSHA: s.info.ExecutionSHA, Change: change})
}

// ExecuteNext runs under the shared replay worker lease, not a second worker.
func (w *Worker) ExecuteNext(ctx context.Context, owner string) (bool, error) {
	if len(w.sources) == 0 {
		return false, nil
	}
	j, err := w.store.ClaimScenarioJob(ctx, owner)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	status, issue := "failed", "source_unavailable"
	source, ok := w.sources[j.Source]
	if ok && source.info.Dataset == j.Dataset && source.info.SourceSHA == j.SourceSHA && source.info.ExecutionSHA == j.ExecutionSHA {
		fitted, fitErr := FitDataset(ctx, w.store, source.request)
		if fitErr == nil && fitted.Scenario != nil && fitted.SourceSHA256 == j.SourceSHA {
			execution, err := scenario.ExecutionHash(*fitted.Scenario)
			if err == nil && execution == j.ExecutionSHA {
				counts := scenario.RoundCount{Total: int64(len(fitted.Recorded))}
				for _, h := range fitted.Recorded {
					if h.Round > 0 {
						counts.Late++
					}
				}
				result, runErr := Run(ctx, w.store, Options{JobID: j.ID, JobOwner: owner, Scenario: *fitted.Scenario, Provenance: fitted.Provenance, Model: fitted.Model, Recorded: []scenario.RoundCount{counts}, RecordedHeights: fitted.Recorded, Change: j.Change, From: source.request.Options.From, To: source.request.Options.To})
				issue = "experiment_incomplete"
				if runErr == nil && result.Summary.Status == "completed" {
					status, issue = "succeeded", ""
				}
			}
		}
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return true, w.store.FinishScenarioJob(cleanup, j.ID, owner, status, issue)
}
