package whatif

// Evidence binds helper references to exact retained source positions. Syntax
// validation alone cannot establish that an ordinal exists in the input.
type answerCoordinate struct{ writer, engine, step string }
type answerKey struct {
	coordinate answerCoordinate
	call       int
}
type Evidence struct {
	Versions  []string
	recorded  map[answerKey]RecordedAnswer
	questions map[Question]bool
	sources   map[Source]bool
	answers   map[answerCoordinate]int
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
	return nil
}
