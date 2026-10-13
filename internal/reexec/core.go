package reexec

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/observe/journal"
)

func serveReplay(ctx context.Context, dir, chain string, id uint64, omit bool, enc *json.Encoder) error {
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
	var count, bad int64
	err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: source, OmitMissingCaptured: omit}, func(s stepdriver.StepResult) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if count > MaxSteps {
			return ErrHelper
		}
		if !s.Match {
			bad++
		}
		return enc.Encode(map[string]any{"type": "step", "id": id, "engine_run": s.EngineRun, "step": s.Step, "input": s.RecordedInputKind, "omitted": s.Omitted, "out_digest": digest(s.OutDigest), "match": s.Match, "outputs": len(s.Outputs)})
	})
	if err != nil {
		code := "replay_error"
		if errors.Is(err, stepdriver.ErrTraceGap) || errors.Is(err, stepdriver.ErrTraceNoSegment) || errors.Is(err, stepdriver.ErrTraceMissingInput) || errors.Is(err, stepdriver.ErrTraceInvalidInput) {
			code = "input_gap"
		} else if errors.Is(err, stepdriver.ErrTraceEnvExhausted) {
			code = "env_exhausted"
		}
		return enc.Encode(map[string]any{"type": "error", "id": id, "code": code})
	}
	return enc.Encode(map[string]any{"type": "done", "id": id, "steps": count, "mismatches": bad, "counterfactual": omit})
}
