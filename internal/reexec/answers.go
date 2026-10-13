package reexec

import "strconv"

type helperAnswerSource struct {
	Writer string `json:"writer_run"`
	Engine uint64 `json:"engine_run"`
	Step   uint64 `json:"step"`
	Call   int    `json:"call"`
	Kind   int    `json:"kind"`
	Key    string `json:"key"`
}

func answerID(writer, engine, step string, call int) string {
	return writer + "/" + engine + "/" + step + "/" + strconv.Itoa(call)
}
func verifiedAnswerSources(p Plan, s Step, raw []helperAnswerSource, used map[string]bool) ([]AnswerSource, error) {
	if len(raw) > 4096 {
		return nil, ErrHelper
	}
	if len(raw) == 0 {
		return nil, nil
	}
	context, ok := p.Contexts[s.Ordinal]
	if !ok {
		return nil, ErrHelper
	}
	sources := make([]AnswerSource, 0, len(raw))
	for _, r := range raw {
		if r.Call < 1 || r.Kind < 0 || r.Kind > 255 || !digestPattern.MatchString(r.Key) {
			return nil, ErrHelper
		}
		key := answerID(r.Writer, strconv.FormatUint(r.Engine, 10), strconv.FormatUint(r.Step, 10), r.Call)
		original, ok := p.Answers[key]
		if !ok || used[key] || original.Context != context || original.Source.Kind != r.Kind || original.Source.Key != r.Key {
			return nil, ErrHelper
		}
		used[key] = true
		sources = append(sources, original.Source)
	}
	return sources, nil
}
