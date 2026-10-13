package reexec

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/observe/journal"
)

func serveReplay(ctx context.Context, dir, chain string, id uint64, omit bool, warmupFrom, compareFrom uint64, answerScope string, schedule *stepdriver.TraceSchedule, enc *json.Encoder) error {
	if schedule != nil && (answerScope != "context" || omit || warmupFrom != 0 || compareFrom != 0) {
		return enc.Encode(map[string]any{"type": "error", "id": id, "code": "input_schedule"})
	}
	raw, err := readChain(chain)
	if err != nil {
		return enc.Encode(map[string]any{"type": "error", "id": id, "code": "replay_error"})
	}
	blocks, err := sim.DecodeChain(raw)
	if err != nil {
		return enc.Encode(map[string]any{"type": "error", "id": id, "code": "replay_error"})
	}
	source, err := sim.NewChainSource(blocks)
	if err != nil {
		return enc.Encode(map[string]any{"type": "error", "id": id, "code": "replay_error"})
	}
	reader, err := journal.OpenReader(nil, dir)
	if err != nil {
		return enc.Encode(map[string]any{"type": "error", "id": id, "code": "input_gap"})
	}
	var count, bad, approximate, warmup int64
	opts := stepdriver.TraceOptions{Schedule: schedule, AnswerScope: answerScope, Blocks: source, OmitMissingCaptured: omit}
	if warmupFrom != 0 || compareFrom != 0 {
		opts.Warmup = &stepdriver.TraceWarmup{FromHeight: warmupFrom, CompareFromHeight: compareFrom}
	}
	if answerScope == "context" {
		answers, e := journal.OpenReader(nil, dir)
		if e != nil {
			return enc.Encode(map[string]any{"type": "error", "id": id, "code": "env_source_mismatch"})
		}
		opts.Answers, e = stepdriver.NewAnswerPool(answers)
		if e != nil {
			return enc.Encode(map[string]any{"type": "error", "id": id, "code": answerErrorCode(e)})
		}
	}
	err = stepdriver.RunTrace(reader, opts, func(s stepdriver.StepResult) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if s.Approximate {
			approximate++
		}
		if s.Warmup {
			warmup++
		}
		if count > MaxSteps {
			return ErrHelper
		}
		if !s.Match {
			bad++
		}
		return enc.Encode(map[string]any{"type": "step", "id": id, "writer_run": s.WriterRun, "engine_run": s.EngineRun, "step": s.Step, "input": s.RecordedInputKind, "omitted": s.Omitted, "out_digest": digest(s.OutDigest), "match": s.Match, "outputs": len(s.Outputs), "context_answers": s.ContextAnswers, "answer_sources": s.AnswerSources, "approximate": s.Approximate, "warmup": s.Warmup, "scheduled_input": s.Scheduled, "suppression_reason": s.SuppressionReason})
	})
	if err != nil {
		code := answerErrorCode(err)
		if errors.Is(err, stepdriver.ErrTraceSchedule) {
			code = "input_schedule"
		} else if errors.Is(err, stepdriver.ErrTraceScheduleReservation) {
			code = "reservation_unavailable"
		}
		if errors.Is(err, stepdriver.ErrTraceGap) || errors.Is(err, stepdriver.ErrTraceNoSegment) || errors.Is(err, stepdriver.ErrTraceMissingInput) || errors.Is(err, stepdriver.ErrTraceInvalidInput) {
			code = "input_gap"
		} else if errors.Is(err, stepdriver.ErrTraceWarmupUnavailable) {
			code = "warmup_unavailable"
		} else if errors.Is(err, stepdriver.ErrTraceEnvExhausted) {
			code = "env_exhausted"
		}
		reply := map[string]any{"type": "error", "id": id, "code": code}
		var failed *stepdriver.TraceError
		if errors.As(err, &failed) {
			reply["writer_run"] = failed.WriterRun
			reply["engine_run"] = failed.EngineRun
			reply["step"] = failed.Step
			reply["approximate"] = failed.Approximate
		}
		return enc.Encode(reply)
	}
	return enc.Encode(map[string]any{"type": "done", "id": id, "steps": count, "mismatches": bad, "counterfactual": omit || answerScope == "context" || schedule != nil, "input_schedule": schedule, "answer_scope": answerScope, "approximate_steps": approximate, "warmup_steps": warmup})
}

func answerErrorCode(err error) string {
	switch {
	case errors.Is(err, stepdriver.ErrTraceEnvAmbiguous):
		return "env_ambiguous"
	case errors.Is(err, stepdriver.ErrTraceEnvSource):
		return "env_source_mismatch"
	case errors.Is(err, stepdriver.ErrTraceHeadMismatch):
		return "head_mismatch"
	case errors.Is(err, stepdriver.ErrTraceAnswerLimit):
		return "answer_limit"
	case errors.Is(err, stepdriver.ErrTraceGap):
		return "input_gap"
	default:
		return "replay_error"
	}
}
