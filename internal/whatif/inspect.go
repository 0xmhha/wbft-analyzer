package whatif

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strconv"

	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

// InspectEvidence independently reproduces the source outputs before accepting
// application-question references from a counterfactual helper.
func InspectEvidence(ctx context.Context, directory string, blocks stepdriver.BlockSource) (*Evidence, error) {
	reader, err := journal.OpenReader(nil, directory)
	if err != nil {
		return nil, err
	}
	var sources []Source
	var answers []RecordedAnswer
	byStep := map[answerCoordinate]Source{}
	writer := ""
	versions := map[string]bool{}
	versionPattern := regexp.MustCompile(`^([0-9a-f]{40}|v[0-9]+\.[0-9]+\.[0-9]+(-[0-9]{14}-[0-9a-f]{12})?)$`)
	var ordinal uint64
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		record, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		ordinal++
		if ordinal > 1000000 {
			return nil, ErrEvidence
		}
		switch body := record.Body.(type) {
		case *journal.SegmentRec:
			writer = body.Run
			version := "unknown"
			if len(body.Commit) <= 96 && versionPattern.MatchString(body.Commit) {
				version = body.Commit
			}
			versions[version] = true
		case *journal.StepRec:
			source := Source{writer, strconv.FormatUint(body.EngineRun, 10), strconv.FormatUint(body.Step, 10), strconv.FormatUint(ordinal, 10)}
			coordinate := answerCoordinate{source.Writer, source.Engine, source.Step}
			if _, exists := byStep[coordinate]; exists {
				return nil, ErrEvidence
			}
			byStep[coordinate] = source
			sources = append(sources, source)
			if len(sources) > 100000 {
				return nil, ErrEvidence
			}
			for index, raw := range body.Env {
				call, err := inputlog.DecodeEnv(raw)
				if err != nil {
					return nil, err
				}
				answers = append(answers, RecordedAnswer{source, index + 1, call.Kind, call.Key.Hex()})
				if len(answers) > 1000000 {
					return nil, ErrEvidence
				}
			}
		}
	}
	evidence, err := NewEvidence(sources)
	if err != nil {
		return nil, err
	}
	for version := range versions {
		evidence.Versions = append(evidence.Versions, version)
	}
	sort.Strings(evidence.Versions)
	if err = evidence.WithAnswers(answers); err != nil {
		return nil, err
	}
	evidence.questions = map[Question]bool{}
	evidence.retiredTimers = map[Source]bool{}
	reader, err = journal.OpenReader(nil, directory)
	if err != nil {
		return nil, err
	}
	count := 0
	fingerprints := map[Question]string{}
	signedInputs := map[Source]string{}
	failures := map[Source]bool{}
	err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: blocks}, func(step stepdriver.StepResult) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !step.Match || step.Approximate || step.Omitted {
			return ErrEvidence
		}
		count++
		source, exists := byStep[answerCoordinate{step.WriterRun, strconv.FormatUint(step.EngineRun, 10), strconv.FormatUint(step.Step, 10)}]
		if !exists {
			return ErrEvidence
		}
		switch input := step.Input.(type) {
		case consensus.Timeout:
			evidence.retiredTimers[source] = true
		case consensus.Message:
			signedInputs[source] = fingerprint(input.Payload)
		case consensus.BroadcastFailed:
			failures[source] = true
		}
		for index, output := range step.Outputs {
			raw, encodeErr := inputlog.EncodeOutputs([]consensus.Output{output})
			if encodeErr != nil {
				return encodeErr
			}
			if len(fingerprints) >= 1000000 {
				return ErrEvidence
			}
			fingerprints[Question{source, strconv.Itoa(index + 1)}] = fingerprint(raw)
			switch output.(type) {
			case consensus.RequestBuild, consensus.Commit:
				evidence.questions[Question{source, strconv.Itoa(index + 1)}] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if count != len(sources) {
		return nil, ErrEvidence
	}
	evidence.actions = map[Question]Action{}
	reader, err = journal.OpenReader(nil, directory)
	if err != nil {
		return nil, err
	}
	pool, err := stepdriver.NewAnswerPool(reader)
	if err != nil {
		return nil, err
	}
	reader, err = journal.OpenReader(nil, directory)
	if err != nil {
		return nil, err
	}
	verified := 0
	err = stepdriver.RunTimedTrace(reader, stepdriver.TimedOptions{Blocks: blocks, Answers: pool}, func(result stepdriver.TimedResult) error {
		if result.Source == nil || !result.Result.Match || result.Generated {
			return ErrEvidence
		}
		source := sourceOf(result.Source)
		actions, err := convertActions(result.Actions)
		if err != nil {
			return err
		}
		if len(actions) != len(result.Result.Outputs) {
			return ErrEvidence
		}
		for index, action := range actions {
			if action.validate(index) != nil || fingerprints[Question{*source, action.Output}] != action.SHA256 {
				return ErrEvidence
			}
			if action.SigningOutput != nil && fingerprints[*action.SigningOutput] != action.SHA256 {
				return ErrEvidence
			}
			if action.Application != nil && (!evidence.questions[*action.Application] || fingerprints[*action.Application] != action.SHA256) {
				return ErrEvidence
			}
			if action.SigningInput != nil {
				switch action.PayloadEvidence {
				case "recorded_signing_result":
					if signedInputs[*action.SigningInput] != action.PayloadSHA256 {
						return ErrEvidence
					}
				case "recorded_signing_failure":
					if !failures[*action.SigningInput] {
						return ErrEvidence
					}
				default:
					return ErrEvidence
				}
			}
			evidence.actions[Question{*source, action.Output}] = action
		}
		verified++
		return ctx.Err()
	})
	if err != nil || verified != count {
		if err != nil {
			return nil, err
		}
		return nil, ErrEvidence
	}
	return evidence, nil
}

func fingerprint(raw []byte) string { hash := sha256.Sum256(raw); return hex.EncodeToString(hash[:]) }
func convertActions(raw []stepdriver.TimedAction) ([]Action, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var out []Action
	if json.Unmarshal(data, &out) != nil || out == nil {
		return nil, ErrEvidence
	}
	return out, nil
}
