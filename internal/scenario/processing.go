package scenario

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/runner"
)

const NativeProcessingPolicy = "native-pre-dispatch/1"

type ProcessingModel struct {
	Policy      string              `json:"policy"`
	Workers     int                 `json:"declared_receive_workers"`
	Timings     []ProcessingTimings `json:"timings"`
	Assumptions []string            `json:"assumptions"`
}

func ValidProcessing(policy string, workers int) bool {
	return policy == "" && workers == 0 || policy == NativeProcessingPolicy && workers >= 1 && workers <= 256
}

// ProcessingTimings preserves measured whole-step intervals independently of
// any simulator policy assigning them to service before an atomic dispatch.
type ProcessingTimings struct {
	Source      Input                `json:"source"`
	Status      string               `json:"status"`
	Scope       string               `json:"scope"`
	From        uint64               `json:"from,string"`
	To          uint64               `json:"to,string"`
	Samples     []ProcessingSample   `json:"samples"`
	Excluded    []ProcessingExcluded `json:"excluded"`
	Assumptions []string             `json:"assumptions"`
}

type ProcessingPoint struct {
	Ordinal int64  `json:"ordinal"`
	File    string `json:"file"`
	Run     string `json:"writer_run"`
	Engine  string `json:"engine_run"`
	Step    string `json:"step"`
	Height  string `json:"height"`
}

type ProcessingSample struct {
	Point        ProcessingPoint `json:"point"`
	Kind         string          `json:"kind"`
	Code         uint64          `json:"code,string"`
	EntryMono    string          `json:"entry_mono_ns"`
	CompleteMono string          `json:"complete_mono_ns"`
	Nanoseconds  int64           `json:"nanoseconds,string"`
}

type ProcessingExcluded struct {
	Point  ProcessingPoint `json:"point"`
	Kind   string          `json:"kind"`
	Reason string          `json:"reason"`
}

func fitProcessingModel(o FitOptions, sources []Input, nodes []Node) (*ProcessingModel, []Issue, error) {
	if !ValidProcessing(o.ProcessingPolicy, o.ProcessingWorkers) || o.ProcessingPolicy != "" && o.Model != EmpiricalCoreModel || o.ProcessingPolicy == "" && len(o.ProcessingTimings) != 0 {
		return nil, nil, errors.New("invalid explicit processing policy")
	}
	if o.ProcessingPolicy == "" {
		return nil, nil, nil
	}
	out := &ProcessingModel{Policy: o.ProcessingPolicy, Workers: o.ProcessingWorkers, Timings: append([]ProcessingTimings{}, o.ProcessingTimings...), Assumptions: []string{
		"native_whole_step_samples_charge_service_before_atomic_dispatch",
		"native_receive_check_cost_unmeasured_and_kept_zero",
		"frame_only_substitute_service_cost_unmeasured_and_kept_zero",
		"receive_worker_count_is_declared_not_measured",
		"unlisted_work_classes_keep_zero_cost",
		"samples_condition_on_recorded_input_kind_and_code_not_internal_branch_or_host_load",
	}}
	if len(out.Timings) > 256 {
		return nil, nil, errors.New("processing source count exceeds bound")
	}
	for i := range out.Timings {
		out.Timings[i].Samples = append([]ProcessingSample{}, out.Timings[i].Samples...)
		out.Timings[i].Excluded = append([]ProcessingExcluded{}, out.Timings[i].Excluded...)
		out.Timings[i].Assumptions = append([]string{}, out.Timings[i].Assumptions...)
	}
	issues := []Issue{}
	seen := map[string]bool{}
	for _, timing := range out.Timings {
		matched := false
		for _, source := range sources {
			matched = matched || reflect.DeepEqual(source, timing.Source)
		}
		node := strings.ToLower(timing.Source.Node)
		if !matched || timing.Source.Kind != "journal" || timing.From != o.From || timing.To != o.To || timing.Scope != "recorded_core_head_plus_one" || seen[node] || len(timing.Samples) > 100000 || len(timing.Excluded) > 100000 {
			return nil, nil, errors.New("processing evidence does not match fitting source")
		}
		seen[node] = true
		if timing.Status != "complete" || len(timing.Samples) == 0 {
			issues = append(issues, Issue{Node: node, Code: "processing_intervals_unavailable"})
		}
		classes := map[string]int{}
		points := map[string]bool{}
		var lastOrdinal int64
		for _, sample := range timing.Samples {
			entry, entryErr := strconv.ParseInt(sample.EntryMono, 10, 64)
			end, endErr := strconv.ParseInt(sample.CompleteMono, 10, 64)
			if entryErr != nil || endErr != nil || entry < 0 || end < entry || end-entry != sample.Nanoseconds || strconv.FormatInt(entry, 10) != sample.EntryMono || strconv.FormatInt(end, 10) != sample.CompleteMono || sample.Point.Ordinal <= lastOrdinal || sample.Nanoseconds < 0 || time.Duration(sample.Nanoseconds) > o.Until {
				return nil, nil, errors.New("processing sample outside model horizon")
			}
			lastOrdinal = sample.Point.Ordinal
			point := sample.Point
			engine, engineErr := strconv.ParseUint(point.Engine, 10, 64)
			step, stepErr := strconv.ParseUint(point.Step, 10, 64)
			height, heightErr := strconv.ParseUint(point.Height, 10, 64)
			pointKey := point.Run + ":" + point.Engine + ":" + point.Step
			if !logs.Identifier(point.Run) || engineErr != nil || stepErr != nil || heightErr != nil || engine == 0 || step == 0 || strconv.FormatUint(engine, 10) != point.Engine || strconv.FormatUint(step, 10) != point.Step || height < o.From || height > o.To || points[pointKey] {
				return nil, nil, errors.New("invalid processing sample source position")
			}
			points[pointKey] = true
			validClass := false
			switch sample.Kind {
			case inputlog.KindMessage:
				validClass = sample.Code == uint64(codec.CodePreprepare) || sample.Code == uint64(codec.CodePrepare) || sample.Code == uint64(codec.CodeCommit) || sample.Code == uint64(codec.CodeRoundChange)
			case inputlog.KindNewHead, inputlog.KindRequest, inputlog.KindBacklog, inputlog.KindTimeout, inputlog.KindCommitResult, inputlog.KindBroadcastFailed, inputlog.KindPeerConnected:
				validClass = sample.Code == 0
			}
			if !validClass {
				return nil, nil, errors.New("unsupported processing sample work class")
			}
			class := fmt.Sprintf("%s:%d", sample.Kind, sample.Code)
			classes[class]++
			if classes[class] == 10001 {
				issues = append(issues, Issue{Node: node, Code: "processing_sample_class_exceeds_limit"})
			}
		}
	}
	for _, node := range nodes {
		if node.RuntimeEvidence != "modeled_core_substitution" && !seen[strings.ToLower(node.Address.Hex())] {
			issues = append(issues, Issue{Node: strings.ToLower(node.Address.Hex()), Code: "processing_source_unavailable"})
		}
	}
	return out, issues, nil
}

func applyProcessing(sc sim.Scenario, nodes []Node, model *ProcessingModel) (sim.Scenario, error) {
	if model == nil {
		return sc, nil
	}
	if len(sc.Nodes) != len(nodes) || model.Policy != NativeProcessingPolicy || !ValidProcessing(model.Policy, model.Workers) {
		return sc, errors.New("processing model execution scope mismatch")
	}
	sc.Nodes = append([]sim.NodeSpec(nil), sc.Nodes...)
	for i, node := range nodes {
		for _, timing := range model.Timings {
			if !strings.EqualFold(node.Address.Hex(), timing.Source.Node) {
				continue
			}
			profile := &sim.ProcessingProfile{Workers: model.Workers, Costs: []sim.ProcessingCost{}}
			indices := map[string]int{}
			for _, sample := range timing.Samples {
				key := fmt.Sprintf("%s:%d", sample.Kind, sample.Code)
				index, exists := indices[key]
				if !exists {
					index = len(profile.Costs)
					indices[key] = index
					profile.Costs = append(profile.Costs, sim.ProcessingCost{Phase: runner.ProcessingCore, Kind: sample.Kind, Code: sample.Code, Samples: []time.Duration{}})
				}
				profile.Costs[index].Samples = append(profile.Costs[index].Samples, time.Duration(sample.Nanoseconds))
			}
			sc.Nodes[i].Processing = profile
		}
	}
	return sc, nil
}
