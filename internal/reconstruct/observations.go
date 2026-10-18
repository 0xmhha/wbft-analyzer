package reconstruct

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
)

func observedInputs(ctx context.Context, m Manifest) (*inputobs.Capture, *InputObservationSummary, error) {
	if m.Inputs == nil {
		return nil, nil, nil
	}
	raw, err := snapshot(ctx, *m.Inputs, inputobs.MaxBytes)
	if err != nil {
		return nil, nil, err
	}
	capture, err := inputobs.Read(ctx, bytes.NewReader(raw))
	if err != nil || capture.Node != m.Node || m.Genesis == nil || capture.GenesisSHA != m.Genesis.SHA256 {
		return nil, nil, errors.New("reconstruction input observation identity or source refused")
	}
	summary := &InputObservationSummary{Format: capture.Format, Normalizer: capture.Normalizer, SHA256: capture.SHA256,
		Bytes: capture.Bytes, Run: capture.Run, FrameRun: capture.FrameRun, BinarySHA: capture.BinarySHA,
		SourceCommit: capture.SourceCommit, GenesisSHA: capture.GenesisSHA, Inputs: int64(len(capture.Inputs)),
		CaptureComplete: capture.Complete, Unavailable: append([]string{}, capture.Unavailable...)}
	for _, input := range capture.Inputs {
		summary.Answers += int64(len(input.Answers))
	}
	for _, scope := range m.Scopes {
		if scope.InputRun == "" {
			continue
		}
		if scope.InputRun != capture.Run || scope.FrameRun != capture.FrameRun || scope.GenesisSHA != capture.GenesisSHA {
			return nil, nil, errors.New("reconstruction declared input execution differs from capture")
		}
		from, _ := time.Parse(time.RFC3339Nano, scope.From)
		to, _ := time.Parse(time.RFC3339Nano, scope.To)
		found := false
		for _, input := range capture.Inputs {
			begin, _ := time.Parse(time.RFC3339Nano, input.BeginWall)
			end, endErr := time.Parse(time.RFC3339Nano, input.EndWall)
			if input.Instance == scope.InputInstance && !begin.Before(from) && !begin.After(to) && endErr == nil && !end.After(to) {
				found = true
				break
			}
		}
		if !found {
			return nil, nil, errors.New("reconstruction declared input instance has no closed source boundary")
		}
		summary.DeclaredScopeMatches++
	}
	return &capture, summary, nil
}

func inputInScope(scope RunScope, source inputobs.Input) bool {
	from, first := time.Parse(time.RFC3339Nano, scope.From)
	to, last := time.Parse(time.RFC3339Nano, scope.To)
	begin, a := time.Parse(time.RFC3339Nano, source.BeginWall)
	end, b := time.Parse(time.RFC3339Nano, source.EndWall)
	return first == nil && last == nil && a == nil && b == nil && source.Instance == scope.InputInstance && !begin.Before(from) && !end.After(to)
}
