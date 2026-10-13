package reexec

import "strconv"

type executionPlan struct {
	steps         []Step
	firstSelected int
	bounded       bool
	unavailable   bool
	unavailableAt int64
	from, compare uint64
}

// planExecution predicts the official helper's emitted source coordinates.
// It never synthesises a source start or removes original completeness issues.
func planExecution(p Plan, depth uint64) executionPlan {
	x := executionPlan{}
	selected := map[string]bool{}
	for _, h := range p.Heights {
		selected[h.Number] = true
	}
	if depth > 0 && depth <= 10000 && p.From > 1 {
		for _, s := range p.Steps {
			if selected[s.Height] && hasIssue(s.Issues, "missing_engine_start") {
				x.bounded = true
				break
			}
		}
	}
	if x.bounded {
		x.compare = p.From
		x.from = 1
		if p.From > depth {
			x.from = p.From - depth
		}
	}
	writer := ""
	started, approximate := false, false
	for _, s := range p.Steps {
		if s.Run != writer {
			writer = s.Run
			started = false
			approximate = false
		}
		if s.Input == "start" {
			started = true
			approximate = false
		}
		if !started && x.bounded {
			height, err := strconv.ParseUint(s.Height, 10, 64)
			if err == nil && height >= x.from {
				started = true
				approximate = true
				if height != x.from {
					if !x.unavailable {
						x.unavailableAt = s.Ordinal
					}
					x.unavailable = true
				}
			}
		}
		if !started {
			continue
		}
		s.Approximate = approximate
		if approximate {
			height, err := strconv.ParseUint(s.Height, 10, 64)
			s.Warmup = err == nil && height < x.compare
		}
		x.steps = append(x.steps, s)
	}
	x.firstSelected = len(x.steps)
	for i, s := range x.steps {
		if selected[s.Height] {
			x.firstSelected = i
			break
		}
	}
	return x
}

func hasIssue(issues []string, want string) bool {
	for _, s := range issues {
		if s == want {
			return true
		}
	}
	return false
}

func approximateComparable(s Step) bool {
	if !s.Approximate || len(s.Issues) != 1 || s.Issues[0] != "missing_engine_start" {
		return false
	}
	return true
}

// A real recorded start restores exact step state even when an earlier
// approximate step made the same height incomplete. Height coverage is retained.
func restoredComparable(s Step, h Height) bool {
	return !s.Approximate && s.Completeness == "complete" && len(h.Issues) == 1 && h.Issues[0] == "missing_engine_start"
}
