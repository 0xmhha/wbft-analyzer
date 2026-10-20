package messages

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"slices"
	"strconv"
	"time"
)

var errSchedulerFrameSource = errors.New("invalid measured scheduler frame source")

func schedulerCounter(s string) bool {
	n, e := strconv.ParseUint(s, 10, 64)
	return e == nil && strconv.FormatUint(n, 10) == s
}
func schedulerMono(s string) (int64, bool) {
	n, e := strconv.ParseInt(s, 10, 64)
	return n, e == nil && n >= 0 && strconv.FormatInt(n, 10) == s
}
func schedulerDecimal(s string) bool {
	n, ok := new(big.Int).SetString(s, 10)
	return ok && n.Sign() >= 0 && n.String() == s
}
func decodeScheduler(raw []byte, out any) error {
	if !uniqueObject(raw) {
		return errSchedulerFrameSource
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errSchedulerFrameSource
	}
	return nil
}
func projectSchedulerEntry(r *Record, x frameRecord) error {
	if (x.EntryMono == nil) != (x.EntryWall == "") {
		return errSchedulerFrameSource
	}
	if x.EntryMono != nil {
		n, ok := schedulerMono(*x.EntryMono)
		if !ok || x.Mono == nil || n > *x.Mono {
			return errSchedulerFrameSource
		}
		wall, e := time.Parse(time.RFC3339Nano, x.EntryWall)
		if e != nil {
			return errSchedulerFrameSource
		}
		r.EntryMono = x.EntryMono
		r.EntryWall = wall.UTC().Format(time.RFC3339Nano)
	}
	return nil
}
func projectSchedulerFrame(r *Record, x frameRecord, fields map[string]json.RawMessage) error {
	allowed := []string{"v", "type", "node", "run", "seq", "t_wall", "t_mono_ns", "journal_segment", "journal_offset"}
	switch x.Type {
	case "scheduler_trace":
		allowed = append(allowed, "scheduler_trace", "clock_source", "cache_trace", "sync_trace")
	case "scheduler_step":
		allowed = append(allowed, "engine_run", "step", "input_kind", "via", "entry_t_mono_ns", "entry_t_wall")
	case "timer_operation":
		allowed = append(allowed, "engine_run", "step", "timer_operation")
	}
	for k, b := range fields {
		if !slices.Contains(allowed, k) || bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
			return errSchedulerFrameSource
		}
	}
	if x.JournalSegment == nil || x.JournalOffset == nil || *x.JournalOffset < 0 || x.Seq == nil || *x.Seq == 0 || x.Mono == nil || *x.Mono < 0 {
		return errSchedulerFrameSource
	}
	r.Journal = &JournalPosition{number(*x.JournalSegment), strconv.FormatInt(*x.JournalOffset, 10)}
	if x.Type == "scheduler_trace" {
		var trace SchedulerTrace
		if decodeScheduler(x.Scheduler, &trace) != nil || trace.Version != "1" || !schedulerCounter(trace.Operations) || !schedulerCounter(trace.Steps) || x.ClockSource != "unavailable" || *x.Mono != 0 || x.Wall != "1970-01-01T00:00:00Z" {
			return errSchedulerFrameSource
		}
		r.Scheduler = &trace
		r.TimerTrace = trace.Version
		r.ClockSource = "unavailable"
		r.Mono = nil
		r.Wall = ""
		return nil
	}
	if x.EngineRun == nil || *x.EngineRun == 0 || x.Step == nil {
		return errSchedulerFrameSource
	}
	r.ClockSource = "recorded"
	if x.Type == "scheduler_step" {
		if *x.Step == 0 || x.InputKind == "" || x.Via == "" {
			return errSchedulerFrameSource
		}
		r.InputKind = x.InputKind
		r.Via = x.Via
		return projectSchedulerEntry(r, x)
	}
	var op TimerOperation
	if decodeScheduler(x.Timer, &op) != nil {
		return errSchedulerFrameSource
	}
	for _, s := range []string{op.Sequence, op.Output, op.ArmEngine, op.ArmStep, op.ArmOutput} {
		if !schedulerCounter(s) {
			return errSchedulerFrameSource
		}
	}
	entry, eok := schedulerMono(op.EntryMono)
	deadline, dok := schedulerMono(op.Deadline)
	if op.Sequence == "0" || !eok || !dok || entry > *x.Mono || !slices.Contains([]string{"core", "restore", "lifecycle", "dequeue"}, op.Source) || !slices.Contains([]string{"arm", "replace", "cancelled", "queued", "pop", "cancel", "clear"}, op.Action) || op.Kinds == nil {
		return errSchedulerFrameSource
	}
	if op.Action == "cancel" || op.Action == "clear" {
		if op.Decode != "not_applicable" || op.TimeoutSHA256 != "" || op.Timer != "" || op.Generation != "" || op.Height != "" || op.Round != "" || op.ArmEngine != "0" || op.ArmStep != "0" || op.ArmOutput != "0" || entry != 0 || deadline != 0 {
			return errSchedulerFrameSource
		}
		seen := map[string]bool{}
		for _, k := range op.Kinds {
			if !slices.Contains([]string{"round", "retry", "future", "round_proposal"}, k) || seen[k] {
				return errSchedulerFrameSource
			}
			seen[k] = true
		}
		if op.Action == "clear" && len(op.Kinds) > 0 {
			return errSchedulerFrameSource
		}
	} else if deadline < entry || op.Decode != "complete" || !shaPattern.MatchString(op.TimeoutSHA256) || !schedulerCounter(op.Generation) || !schedulerDecimal(op.Height) || !schedulerDecimal(op.Round) || !slices.Contains([]string{"round", "retry", "future", "round_proposal"}, op.Timer) || len(op.Kinds) > 0 {
		return errSchedulerFrameSource
	}
	r.Timer = &op
	r.Height = op.Height
	r.Round = op.Round
	return nil
}

// This reader validates the snapshot, without issuing consensus verdicts or
// authenticating coordinates against raw journal bytes. Timer decisions stay
// in the inspector; the analyzer retains closed metadata and source pointers.
func validateSchedulerFrames(rows []Record, lost map[ownScope]bool, conflicted bool) error {
	groups := map[ownScope][]Record{}
	for _, r := range rows {
		groups[ownKey(r).ownScope] = append(groups[ownKey(r).ownScope], r)
	}
	for scope, rs := range groups {
		var decl *SchedulerTrace
		ops, steps := uint64(0), uint64(0)
		seqs := map[string]bool{}
		positions := map[JournalPosition]bool{}
		stepIDs := map[[2]string]bool{}
		measured := false
		for _, r := range rs {
			if r.Type != "own_input" {
				measured = true
			}
			if r.Scheduler != nil {
				if decl != nil {
					return errSchedulerFrameSource
				}
				decl = r.Scheduler
			}
		}
		if !measured && decl == nil {
			continue
		}
		if decl == nil || lost[scope] || conflicted {
			return errSchedulerFrameSource
		}
		for _, r := range rs {
			if r.Journal == nil || positions[*r.Journal] {
				return errSchedulerFrameSource
			}
			positions[*r.Journal] = true
			switch r.Type {
			case "timer_operation":
				ops++
				if r.Timer == nil || seqs[r.Timer.Sequence] {
					return errSchedulerFrameSource
				}
				seqs[r.Timer.Sequence] = true
			case "scheduler_step", "own_input":
				steps++
				id := [2]string{r.EngineRun, r.Step}
				if !positiveDecimal(r.EngineRun) || !positiveDecimal(r.Step) || stepIDs[id] {
					return errSchedulerFrameSource
				}
				stepIDs[id] = true
			}
		}
		if number(ops) != decl.Operations || number(steps) != decl.Steps {
			return errSchedulerFrameSource
		}
		for n := uint64(1); n <= ops; n++ {
			if !seqs[number(n)] {
				return errSchedulerFrameSource
			}
		}
	}
	return nil
}
