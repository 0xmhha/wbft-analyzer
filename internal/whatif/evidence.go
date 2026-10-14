package whatif

import (
	"sort"
	"strconv"
)

// Evidence binds helper references to exact retained source positions. Syntax
// validation alone cannot establish that an ordinal exists in the input.
type answerCoordinate struct{ writer, engine, step string }
type answerKey struct {
	coordinate answerCoordinate
	call       int
}
type Evidence struct {
	retiredTimers   map[Source]bool
	Versions        []string
	recorded        map[answerKey]RecordedAnswer
	questions       map[Question]bool
	sources         map[Source]bool
	answers         map[answerCoordinate]int
	actions         map[Question]Action
	executions      map[string][]Action
	consumedSources map[Source]bool
	consumedSigning map[Question]bool
}

func NewEvidence(sources []Source) (*Evidence, error) {
	if len(sources) == 0 || len(sources) > 100000 {
		return nil, ErrEvidence
	}
	e := &Evidence{sources: map[Source]bool{}, answers: map[answerCoordinate]int{}}
	for _, source := range sources {
		if !sourceValid(&source) || e.sources[source] {
			return nil, ErrEvidence
		}
		e.sources[source] = true
		e.answers[answerCoordinate{source.Writer, source.Engine, source.Step}]++
	}
	return e, nil
}

func (e *Evidence) Validate(s Step, previous uint64) error {
	if e == nil {
		return ErrEvidence
	}
	if err := s.Validate(previous); err != nil {
		return err
	}
	for _, source := range []*Source{s.Source, s.Cause, s.Arm, s.Signing} {
		if source != nil && !e.sources[*source] {
			return ErrEvidence
		}
	}
	for _, question := range s.Questions {
		if !e.sources[question.Source] || !e.questions[question] {
			return ErrEvidence
		}
	}
	// Environment answers omit ordinals in the core protocol. Require a unique
	// recorded writer/engine/step before joining them to a retained source.
	for _, answer := range s.Answers {
		matches := e.answers[answerCoordinate{answer.Writer, answer.Engine, answer.Step}]
		original, exists := e.recorded[answerKey{answerCoordinate{answer.Writer, answer.Engine, answer.Step}, answer.Call}]
		if matches != 1 || !exists || int(original.Kind) != answer.Kind || original.Key != answer.Key {
			return ErrEvidence
		}
	}
	if err := e.validateActions(s); err != nil {
		return err
	}
	return nil
}

func (e *Evidence) validateActions(s Step) error {
	if s.Actions == nil {
		return nil
	}
	if s.Source != nil {
		if e.consumedSources[*s.Source] || e.retiredTimers[*s.Source] {
			return ErrEvidence
		}
		for index, action := range s.RecordedActions {
			original, exists := e.actions[Question{*s.Source, action.Output}]
			if !exists || actionIdentity(original) != actionIdentity(action) || index >= 100000 {
				return ErrEvidence
			}
		}
		// Refuse truncation of an original output list, including zero-length
		// claims for a source which actually produced an output.
		if _, exists := e.actions[Question{*s.Source, strconv.Itoa(len(s.RecordedActions) + 1)}]; exists {
			return ErrEvidence
		}
	}
	pendingSigning := map[Question]bool{}
	for _, action := range s.Actions {
		for _, q := range []*Question{action.SigningOutput, action.Application} {
			if q == nil {
				continue
			}
			original, exists := e.actions[*q]
			if !exists || actionIdentity(original) != actionIdentity(action) {
				return ErrEvidence
			}
		}
		if action.SigningOutput != nil {
			q := *action.SigningOutput
			if pendingSigning[q] || e.consumedSigning[q] {
				return ErrEvidence
			}
			pendingSigning[q] = true
		}
		if action.SigningInput != nil && !e.sources[*action.SigningInput] {
			return ErrEvidence
		}
	}
	if s.Generated {
		parent := e.executions[s.Parent]
		index, err := parseOutput(s.ParentOutput, len(parent))
		if err != nil {
			return err
		}
		kind := parent[index].Kind
		switch s.Input {
		case "timeout":
			if kind != "arm_timer" || s.ArmExecution != s.Parent {
				return ErrEvidence
			}
		case "message", "broadcast_failed":
			if kind != "broadcast" {
				return ErrEvidence
			}
		case "commit_result":
			if kind != "commit" {
				return ErrEvidence
			}
		case "backlog", "request":
			if kind != "schedule" {
				return ErrEvidence
			}
		default:
			return ErrEvidence
		}
	}
	if e.executions == nil {
		e.executions = map[string][]Action{}
	}
	if e.consumedSources == nil {
		e.consumedSources = map[Source]bool{}
	}
	if s.Source != nil {
		e.consumedSources[*s.Source] = true
	}
	if e.consumedSigning == nil {
		e.consumedSigning = map[Question]bool{}
	}
	for q := range pendingSigning {
		e.consumedSigning[q] = true
	}
	e.executions[s.Execution] = s.Actions
	return nil
}

// ValidateFailure locates the first failed execution without creating an input
// ordinal for a generated input or treating a missing signature as completion.
func (e *Evidence) ValidateFailure(execution string, parent, output *string, cause, source *Source, previous uint64, code string) error {
	n, err := strconv.ParseUint(execution, 10, 64)
	if err != nil || !decimal(execution, false, 64) || previous == ^uint64(0) || n != previous+1 || parent == nil || output == nil || !decimal(*parent, true, 64) || !decimal(*output, true, 64) {
		return ErrEvidence
	}
	for _, s := range []*Source{cause, source} {
		if !sourceValid(s) || s != nil && !e.sources[*s] {
			return ErrEvidence
		}
	}
	p, _ := strconv.ParseUint(*parent, 10, 64)
	if p >= n {
		return ErrEvidence
	}
	if p == 0 {
		if *output != "0" || code == "signing_unavailable" {
			return ErrEvidence
		}
		return nil
	}
	index, err := parseOutput(*output, len(e.executions[*parent]))
	if err != nil || cause == nil {
		return ErrEvidence
	}
	if code == "signing_unavailable" && e.executions[*parent][index].Kind != "broadcast" {
		return ErrEvidence
	}
	return nil
}

// Complete requires all original external and suppressed internal slots.
// Original timeout slots are independently classified from retained inputs
// and replaced by generated expiries. Helper counts cannot prove either set.
func (e *Evidence) Complete() error {
	if e == nil || len(e.consumedSources) != len(e.sources)-len(e.retiredTimers) {
		return ErrEvidence
	}
	return nil
}

func (e *Evidence) RetiredTimers() []Source {
	out := make([]Source, 0, len(e.retiredTimers))
	for source := range e.retiredTimers {
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := strconv.ParseUint(out[i].Ordinal, 10, 64)
		b, _ := strconv.ParseUint(out[j].Ordinal, 10, 64)
		return a < b
	})
	return out
}
