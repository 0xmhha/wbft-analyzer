package whatif

import (
	"context"
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
	reader, err = journal.OpenReader(nil, directory)
	if err != nil {
		return nil, err
	}
	count := 0
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
		for index, output := range step.Outputs {
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
	return evidence, nil
}
