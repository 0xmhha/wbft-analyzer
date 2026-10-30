package whatif

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/source/domainprofile"
	"os"
	"strconv"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

func sourceOf(source *stepdriver.TimedSource) *Source {
	if source == nil {
		return nil
	}
	return &Source{source.Writer, strconv.FormatUint(source.Engine, 10), strconv.FormatUint(source.Step, 10), strconv.FormatUint(source.Ordinal, 10)}
}

// ServeTimed delegates all execution to the public core library. This adapter
// only serializes bounded observations and never signs or invents app answers.
func ServeTimed(ctx context.Context, directory, chain string, id uint64, policy Policy, enc *json.Encoder) error {
	sendError := func(code string) error { return enc.Encode(map[string]any{"type": "error", "id": id, "code": code}) }
	raw, _, err := policy.Canonical()
	if err != nil {
		return sendError("timer_policy")
	}
	var corePolicy stepdriver.TimerPolicy
	if json.Unmarshal(raw, &corePolicy) != nil {
		return sendError("timer_policy")
	}
	file, err := os.Open(chain)
	if err != nil {
		return sendError("input_gap")
	}
	raw, err = readBoundedChain(file)
	_ = file.Close()
	if err != nil {
		return sendError("input_gap")
	}
	blocks, err := sim.DecodeChain(raw)
	if err != nil {
		return sendError("input_gap")
	}
	source, err := sim.NewChainSource(blocks)
	if err != nil {
		return sendError("input_gap")
	}
	reader, err := journal.OpenReader(nil, directory)
	if err != nil {
		return sendError("input_gap")
	}
	answers, err := stepdriver.NewAnswerPool(reader)
	if err != nil {
		if domainprofile.Unsupported(err) || errors.Is(err, stepdriver.ErrUnsupported) {
			return sendError("unsupported_profile")
		}
		return sendError("input_gap")
	}
	reader, err = journal.OpenReader(nil, directory)
	if err != nil {
		return sendError("input_gap")
	}
	var count, generated, sourced uint64
	var scopes []Scope
	err = stepdriver.RunTimedTrace(reader, stepdriver.TimedOptions{Blocks: source, Answers: answers, Policy: corePolicy, Complete: func(result stepdriver.TimedCompletion) error {
		if !result.TimerTraceValidated {
			return ErrEvidence
		}
		scopes = append(scopes, Scope{result.Writer, strconv.FormatUint(result.Engine, 10), strconv.FormatUint(result.Execution, 10), strconv.FormatInt(int64(result.Mono), 10), result.PendingInternal, result.QueuedTimers, result.ArmedTimers})
		return nil
	}}, func(result stepdriver.TimedResult) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if result.Generated {
			generated++
		} else {
			sourced++
		}
		if count > 100000 {
			return ErrEvidence
		}
		var deadline *string
		if result.Deadline != nil {
			value := strconv.FormatInt(int64(*result.Deadline), 10)
			deadline = &value
		}
		questions := []Question{}
		for _, q := range result.ApplicationSources {
			questions = append(questions, Question{*sourceOf(&q.Source), strconv.FormatUint(q.Output, 10)})
		}
		state := State{result.State.Running, result.State.Height, result.State.Round, result.State.State}
		actions, err := convertActions(result.Actions)
		if err != nil {
			return err
		}
		recorded, err := convertActions(result.RecordedActions)
		if err != nil {
			return err
		}
		step := Step{Actions: actions, RecordedActions: recorded, ParentOutput: strconv.FormatUint(result.ParentOutput, 10), Execution: strconv.FormatUint(result.Execution, 10), Mono: strconv.FormatInt(int64(result.Mono), 10), State: state, Source: sourceOf(result.Source), Cause: sourceOf(result.Cause), Parent: strconv.FormatUint(result.ParentExecution, 10), Arm: sourceOf(result.Arm), ArmExecution: strconv.FormatUint(result.ArmExecution, 10), Deadline: deadline, Signing: sourceOf(result.Evidence), Questions: questions, Generated: result.Generated, Suppression: result.Suppression, Input: inputlog.Kind(result.Result.Input), Digest: result.Result.OutDigest.Hex(), Outputs: len(result.Result.Outputs), Comparable: result.Source != nil && result.Suppression == "", Match: result.Result.Match, Counterfactual: result.Counterfactual, Model: result.Model}
		encoded, err := json.Marshal(step)
		if err != nil {
			return err
		}
		var reply map[string]json.RawMessage
		if json.Unmarshal(encoded, &reply) != nil {
			return ErrEvidence
		}
		reply["type"] = json.RawMessage(`"timed_step"`)
		reply["id"], _ = json.Marshal(id)
		reply["answer_sources"], err = json.Marshal(result.Result.AnswerSources)
		if err != nil {
			return err
		}
		return enc.Encode(reply)
	})
	if err != nil {
		code := "replay_error"
		switch {
		case domainprofile.Unsupported(err), errors.Is(err, stepdriver.ErrUnsupported):
			code = "unsupported_profile"
		case errors.Is(err, stepdriver.ErrTraceSigningUnavailable):
			code = "signing_unavailable"
		case errors.Is(err, stepdriver.ErrTraceTiming):
			code = "timing_unavailable"
		case errors.Is(err, stepdriver.ErrTraceEnvExhausted):
			code = "env_exhausted"
		case errors.Is(err, stepdriver.ErrTraceScheduleReservation):
			code = "reservation_unavailable"
		case errors.Is(err, stepdriver.ErrTraceAnswerLimit):
			code = "answer_limit"
		}
		reply := map[string]any{"type": "error", "id": id, "code": code, "steps": strconv.FormatUint(count, 10)}
		var failed *stepdriver.TimedError
		if errors.As(err, &failed) {
			reply["execution_step"] = strconv.FormatUint(failed.Execution, 10)
			reply["cause"] = sourceOf(failed.Cause)
			reply["source_input"] = sourceOf(failed.Source)
			reply["parent_execution_step"] = strconv.FormatUint(failed.ParentExecution, 10)
			reply["parent_output"] = strconv.FormatUint(failed.ParentOutput, 10)
		}
		return enc.Encode(reply)
	}
	if count == 0 || len(scopes) == 0 {
		return sendError("input_gap")
	}
	return enc.Encode(map[string]any{"type": "timed_done", "id": id, "steps": strconv.FormatUint(count, 10), "source_steps": strconv.FormatUint(sourced, 10), "generated_steps": strconv.FormatUint(generated, 10), "counterfactual": true, "execution_model": Model, "timer_policy": policy, "horizon": "recorded_source_end", "future_tail_generated": false, "timer_trace_validated": true, "scopes": scopes})
}
