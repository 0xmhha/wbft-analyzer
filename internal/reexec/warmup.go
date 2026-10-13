package reexec

func recordWarmup(w *Warmup, s Step) {
	w.Steps++
	if w.FirstSource == nil {
		n := s.Ordinal
		w.FirstSource = &n
	}
	n := s.Ordinal
	w.LastSource = &n
	switch s.Class {
	case "match":
		w.Matches++
	case "output_diverged", "env_mismatch", "env_exhausted":
		w.Mismatches++
	default:
		w.NotComparable++
	}
	if s.Class != "match" && w.FirstDifference == nil {
		w.FirstDifference = &s
	}
}

func finishWarmup(w *Warmup) {
	switch {
	case w.Status == "failed":
	case w.NotComparable > 0:
		w.Status = "partial"
	case w.Mismatches > 0:
		w.Status = "diverged"
	case w.Steps > 0:
		w.Status = "complete"
	default:
		w.Status = "not_required"
	}
}

func classifyStep(s Step, r reply, comparable bool) Step {
	if !comparable {
		s.Class = "not_comparable"
		return s
	}
	s.Replayed = r.Digest
	s.Class = "match"
	if !*r.Match {
		s.Class = "output_diverged"
		if s.Recorded == r.Digest {
			s.Class = "env_mismatch"
		}
	}
	return s
}
