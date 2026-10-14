package runtimeobs

import "strconv"

// TaskEvidence preserves exact source candidates, including duplicates.
// Intervals describe measured code boundaries, not consensus acceptance.
type TaskEvidence struct {
	ID        string     `json:"id"`
	State     string     `json:"state"`
	StartLine int        `json:"start_line"`
	EndLine   int        `json:"end_line"`
	Stages    []Point    `json:"stages"`
	Intervals []Interval `json:"intervals"`
}
type Interval struct {
	Definition  string `json:"definition"`
	FromLine    int    `json:"from_line"`
	ToLine      int    `json:"to_line"`
	Nanoseconds string `json:"nanoseconds"`
}

func projectEvidence(t Task, points []Point, complete bool) TaskEvidence {
	out := TaskEvidence{ID: t.ID, State: t.State, StartLine: t.StartLine, EndLine: t.EndLine, Stages: []Point{}, Intervals: []Interval{}}
	byStage := map[string]Point{}
	for _, raw := range t.Stages {
		if raw.Line < 1 || raw.Line > len(points) {
			out.State = "incomplete"
			return out
		}
		p := points[raw.Line-1]
		out.Stages = append(out.Stages, p)
		byStage[p.Stage] = p
	}
	if !complete || t.State != "observed_result" && t.State != "observed_cancellation" || t.StartLine < 1 || t.StartLine > len(points) {
		return out
	}
	pair := func(name string, a, b Point) {
		from, e1 := strconv.ParseInt(a.Mono, 10, 64)
		to, e2 := strconv.ParseInt(b.Mono, 10, 64)
		if a.Line < 1 || b.Line < 1 || e1 != nil || e2 != nil || from < 0 || to < from {
			return
		}
		out.Intervals = append(out.Intervals, Interval{name, a.Line, b.Line, strconv.FormatInt(to-from, 10)})
	}
	pair("worker_entry_to_task_offer", points[t.StartLine-1], byStage["task_offer"])
	pair("task_offer_to_seal_entry", byStage["task_offer"], byStage["seal_enter"])
	terminal := "seal_result"
	if t.State == "observed_cancellation" {
		terminal = "seal_cancel"
	}
	pair("seal_entry_to_"+terminal, byStage["seal_enter"], byStage[terminal])
	return out
}
