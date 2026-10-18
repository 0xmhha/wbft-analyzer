package reconstruct

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/ethereum/go-ethereum/common"
)

const maxExecutionJSON = 64 << 20
const observationSourceCommit = "740526d0375a8aca817b580e7a4bfc4c1028ae29"

// Execute runs only an explicitly associated, closed input capture. Older
// sources retain their readiness assessment; source presence is not promoted
// to a completed comparison. Every core has all improvements disabled.
func Execute(ctx context.Context, m Manifest, from, to string) (ExecutionResult, error) {
	a, err := Assess(ctx, m, from, to)
	if err != nil {
		return ExecutionResult{}, err
	}
	result := ExecutionResult{Assessment: a, ExecutionVersion: ExecutionVersion, CoreVersion: reexec.LinkedCommit(), AllImprovementsOff: true, ComparisonModel: ComparisonModel, Executions: []HeightExecution{}}
	result.Phase = "reconstructed_execution"
	capture, _, err := observedInputs(ctx, m)
	if err != nil {
		return ExecutionResult{}, err
	}
	missing := ""
	switch {
	case capture == nil:
		missing = "processing_observations_unavailable"
	case !capture.Complete:
		missing = "processing_capture_incomplete"
	case capture.SourceCommit != observationSourceCommit:
		missing = "processing_source_version_unavailable"
	case m.Frames == nil || m.Chain == nil || m.Genesis == nil:
		missing = "execution_source_bundle_incomplete"
	case result.CoreVersion == "unknown":
		missing = "linked_core_identity_unavailable"
	}
	if missing != "" {
		for i := range result.Heights {
			if !slices.Contains(result.Heights[i].Issues, missing) {
				result.Heights[i].Issues = append(result.Heights[i].Issues, missing)
			}
		}
		return boundedExecution(result)
	}
	cfg, err := genesisConfig(ctx, m)
	if err != nil {
		return ExecutionResult{}, err
	}
	raw, err := snapshot(ctx, *m.Chain, 128<<20)
	if err != nil {
		return ExecutionResult{}, err
	}
	blocks, err := sim.DecodeChain(raw)
	if err != nil {
		return ExecutionResult{}, errors.New("reconstruction chain refused")
	}
	chain, err := sim.NewChainSource(blocks)
	if err != nil {
		return ExecutionResult{}, errors.New("reconstruction chain refused")
	}
	log, err := executionLogIndex(ctx, m)
	if err != nil {
		return ExecutionResult{}, err
	}
	frames, err := readFrameCoverage(ctx, m)
	if err != nil {
		var refusal envFailure
		if !errors.As(err, &refusal) {
			return ExecutionResult{}, err
		}
		for i := range result.Heights {
			if !slices.Contains(result.Heights[i].Issues, refusal.Reason) {
				result.Heights[i].Issues = append(result.Heights[i].Issues, refusal.Reason)
			}
		}
		return boundedExecution(result)
	}
	index := map[string]int{}
	for i, height := range result.Heights {
		index[height.Height] = i
	}
	instances := map[string][]inputobs.Input{}
	order := []string{}
	for _, source := range capture.Inputs {
		if _, ok := instances[source.Instance]; !ok {
			order = append(order, source.Instance)
		}
		instances[source.Instance] = append(instances[source.Instance], source)
	}
	bytesUsed := 0
	for _, instance := range order {
		inputs := instances[instance]
		touched := map[string]bool{}
		for _, source := range inputs {
			for _, height := range []string{source.Before.Height, source.After.Height} {
				if _, wanted := index[height]; wanted {
					touched[height] = true
				}
			}
		}
		if len(touched) == 0 {
			continue
		}
		var scope *RunScope
		for i := range m.Scopes {
			candidate := &m.Scopes[i]
			if candidate.InputRun == capture.Run && candidate.InputInstance == instance {
				if scope != nil {
					return ExecutionResult{}, errors.New("reconstruction instance has multiple declared log runs")
				}
				scope = candidate
			}
		}
		reason := ""
		if scope == nil {
			reason = "processing_instance_scope_unavailable"
		} else {
			anchored := false
			for _, declared := range a.Sources.ProcessingScopes {
				if declared.LogRun == scope.LogRun && declared.FrameRun == scope.FrameRun && declared.Status == "declared_content_anchored" {
					anchored = true
				}
			}
			if !anchored {
				reason = "processing_scope_content_unanchored"
			}
		}
		if reason != "" {
			for _, height := range result.Heights {
				if touched[height.Height] {
					result.Executions = append(result.Executions, HeightExecution{Height: height.Height, Status: "partial", Issues: []string{reason}, Steps: []ExecutionStep{}})
				}
			}
			continue
		}
		core := newObservedCore(cfg, common.HexToAddress(m.Node), chain.Reader())
		bindings := &inputBindings{}
		runs := map[string]*HeightExecution{}
		get := func(height string) *HeightExecution {
			if _, wanted := index[height]; !wanted {
				return nil
			}
			if runs[height] == nil {
				runs[height] = &HeightExecution{Height: height, Run: scope.LogRun, Status: "partial", Issues: []string{}, Steps: []ExecutionStep{}}
			}
			return runs[height]
		}
		stopped := "processing_window_end_unavailable"
		for ordinal, source := range inputs {
			if err := ctx.Err(); err != nil {
				return ExecutionResult{}, err
			}
			height, round := source.Before.Height, source.Before.Round
			if source.Kind == "start" {
				height, round = source.After.Height, source.After.Round
			}
			run := get(height)
			step := ExecutionStep{Input: ReconstructedInput{Ordinal: strconv.Itoa(ordinal + 1), Kind: source.Kind, Height: height, Round: round, Source: Point{Kind: "processing_boundary", File: "input_observations", Line: source.BeginLine, Run: capture.Run, Sequence: source.Ordinal}, ObservationInstance: instance, ProcessingMonoNS: source.BeginMono, ReceiveClock: "actual_processing_boundary_not_wire_arrival", Via: "unbound"}, Observed: []Projection{}, Computed: []Projection{}, Differences: []DifferenceCandidate{}, Issues: []string{}}
			var failure error
			if !inputInScope(*scope, source) {
				failure = refusedBinding("processing_input_outside_declared_scope")
			}
			rows, err := log.window(source, scope.LogRun)
			if err != nil {
				failure = err
			}
			entries := eventsOf(rows)
			if ordinal == 0 {
				starts := 0
				for _, entry := range entries {
					if entry.Record.Kind == event.EngineStart && field(entry, "address") == m.Node {
						starts++
					}
				}
				if source.Kind != "start" || starts != 1 {
					failure = refusedBinding("processing_engine_start_unbound")
				}
			}
			for _, answer := range source.Answers {
				point := &Point{Kind: "application_answer", File: "input_observations", Line: answer.Line, Run: capture.Run, Sequence: source.Ordinal}
				if answer.Method == "head" && step.Input.Head == nil {
					step.Input.Head = point
				} else if answer.Method != "head" && step.Input.Application == nil {
					step.Input.Application = point
				}
			}
			step.Observed = append(step.Observed, statePhase(recordedView(source.Before), "state_before"), statePhase(recordedView(source.After), "state_after"))
			before := computedView(cfg, core.state.Snapshot())
			step.Computed = append(step.Computed, statePhase(before, "state_before"))
			step.Differences = append(step.Differences, viewDifferences(recordedView(source.Before), before, "before")...)
			if len(step.Differences) != 0 {
				failure = refusedBinding("core_context_comparison_stopped")
			}
			var bound boundInput
			if failure == nil {
				step.Input.Content, failure = processingContent(source, *scope, m.Node, frames, log)
				if step.Input.Content != nil {
					step.Input.ContentModel = "direct_processing_bytes_with_content_corroboration"
				}
			}
			if failure == nil {
				_, failure = sourceTimerFire(source, entries)
			}
			if failure == nil {
				bound, failure = bindings.bind(source)
			}
			if failure == nil {
				step.Input.Via, step.Input.TimerArm = bound.via, bound.arm
				if timeout, ok := bound.in.(consensus.Timeout); ok {
					step.Input.DerivedTimerGen = strconv.FormatUint(timeout.Gen, 10)
				} else if bound.future != nil {
					step.Input.DerivedTimerGen = strconv.FormatUint(bound.future.Gen, 10)
				}
				var outputs []consensus.Output
				outputs, failure = core.apply(source, bound)
				if failure == nil {
					step.CoreApplied = true
					result.CoreExecuted = true
					after := computedView(cfg, core.state.Snapshot())
					step.Computed = append(step.Computed, statePhase(after, "state_after"))
					step.Differences = append(step.Differences, viewDifferences(recordedView(source.After), after, "after")...)
					arms, armErr := sourceArms(source, outputs, entries)
					if armErr != nil {
						failure = armErr
					} else {
						observed, computed, actionErr := actionProjections(source, outputs, rows, arms)
						if actionErr != nil {
							failure = actionErr
						} else {
							step.Observed = append(step.Observed, observed...)
							step.Computed = append(step.Computed, computed...)
							step.Differences = append(step.Differences, actionDifferences(observed, computed)...)
							failure = bindings.retain(source, outputs, arms)
						}
					}
					if len(viewDifferences(recordedView(source.After), after, "after")) != 0 {
						failure = refusedBinding("core_context_comparison_stopped")
					}
				}
			}
			if failure != nil {
				var refusal envFailure
				if !errors.As(failure, &refusal) {
					return ExecutionResult{}, failure
				}
				stopped = refusal.Reason
				step.Issues = append(step.Issues, refusal.Reason)
				if refusal.Method != "" {
					step.Differences = append(step.Differences, DifferenceCandidate{Kind: refusal.Reason, Expected: &Projection{Kind: "application_binding", Method: refusal.Method, ArgumentSHA256: refusal.ExpectedSHA}, Actual: &Projection{Kind: "application_binding", Method: refusal.Method, ArgumentSHA256: refusal.ActualSHA}})
				}
			}
			if run != nil {
				encoded, err := json.Marshal(step)
				if err != nil || len(encoded) > 256<<10 || bytesUsed+len(encoded) > maxExecutionJSON {
					return ExecutionResult{}, errors.New("reconstruction execution exceeds output limit")
				}
				bytesUsed += len(encoded)
				run.Steps = append(run.Steps, step)
				run.Differences += int64(len(step.Differences))
			}
			if failure != nil {
				break
			}
			if run != nil && (source.Kind == "stop" || advanced(height, source.After.Height)) {
				run.Status = "complete"
			}
			if advanced(to, source.After.Height) {
				stopped = ""
				break
			}
		}
		for _, height := range result.Heights {
			if !touched[height.Height] {
				continue
			}
			run := get(height.Height)
			if run.Status != "complete" {
				run.Issues = append(run.Issues, "processing_window_not_completed")
				if stopped != "" {
					run.Issues = append(run.Issues, stopped)
				}
			}
			result.Executions = append(result.Executions, *run)
		}
	}
	for i := range result.Heights {
		height := &result.Heights[i]
		found, complete := false, true
		for _, run := range result.Executions {
			if run.Height == height.Height {
				found, complete = true, complete && run.Status == "complete"
			}
		}
		if found && complete {
			height.Status, height.Issues = "complete", []string{}
			result.CoreExecuted = true
		} else if found {
			height.Status = "partial"
			height.Issues = append(height.Issues, "reconstructed_execution_incomplete")
		}
	}
	return boundedExecution(result)
}

func boundedExecution(result ExecutionResult) (ExecutionResult, error) {
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > maxExecutionJSON {
		return ExecutionResult{}, errors.New("reconstruction execution exceeds output limit")
	}
	return result, nil
}

func statePhase(value Projection, phase string) Projection { value.Kind = phase; return value }

func advanced(before, after string) bool {
	a, ok := new(big.Int).SetString(before, 10)
	b, valid := new(big.Int).SetString(after, 10)
	return ok && valid && b.Cmp(a) > 0
}
