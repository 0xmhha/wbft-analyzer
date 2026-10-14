package runtimeobs

// EngineEvidence keeps precision-safe identities and all original candidates.
// Lifecycle completion does not establish execution-model completeness.
type EngineEvidence struct {
	Configuration string  `json:"configuration"`
	Configs       []Point `json:"configs"`
	Created       Point   `json:"created"`
	ID            string  `json:"id"`
	ParentID      string  `json:"parent_id"`
	CreatedLine   int     `json:"created_line"`
	State         string  `json:"state"`
	Stages        []Point `json:"stages"`
}

func projectEngineEvidence(e Engine, points []Point) EngineEvidence {
	out := EngineEvidence{Configuration: e.Configuration, Configs: []Point{}, ID: e.ID, ParentID: e.ParentID, CreatedLine: e.CreatedLine, State: e.State, Stages: []Point{}}
	if e.CreatedLine < 1 || e.CreatedLine > len(points) {
		out.State = "incomplete"
		return out
	}
	out.Created = points[e.CreatedLine-1]
	for _, config := range e.Configs {
		if config.Line < 1 || config.Line > len(points) {
			out.Configuration = "incomplete"
			return out
		}
		out.Configs = append(out.Configs, points[config.Line-1])
	}
	for _, s := range e.Stages {
		if s.Line < 1 || s.Line > len(points) {
			out.State = "incomplete"
			return out
		}
		out.Stages = append(out.Stages, points[s.Line-1])
	}
	return out
}
