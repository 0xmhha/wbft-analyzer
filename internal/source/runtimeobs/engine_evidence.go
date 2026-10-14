package runtimeobs

// EngineEvidence keeps precision-safe identities and all original candidates.
// Lifecycle completion does not establish execution-model completeness.
type EngineEvidence struct {
	Created     Point   `json:"created"`
	ID          string  `json:"id"`
	ParentID    string  `json:"parent_id"`
	CreatedLine int     `json:"created_line"`
	State       string  `json:"state"`
	Stages      []Point `json:"stages"`
}

func projectEngineEvidence(e Engine, points []Point) EngineEvidence {
	out := EngineEvidence{ID: e.ID, ParentID: e.ParentID, CreatedLine: e.CreatedLine, State: e.State, Stages: []Point{}}
	if e.CreatedLine < 1 || e.CreatedLine > len(points) {
		out.State = "incomplete"
		return out
	}
	out.Created = points[e.CreatedLine-1]
	for _, s := range e.Stages {
		if s.Line < 1 || s.Line > len(points) {
			out.State = "incomplete"
			return out
		}
		out.Stages = append(out.Stages, points[s.Line-1])
	}
	return out
}
