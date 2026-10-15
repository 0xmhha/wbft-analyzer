package scenario

import (
	"errors"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
)

// EmpiricalTimings supplies measured delays to a fake application. It does not
// declare the observed executor policy, node options, or a complete runtime.
type EmpiricalTimings struct {
	Source        Input               `json:"source"`
	Build         []AppSample         `json:"build"`
	Import        []AppSample         `json:"import"`
	Excluded      []EmpiricalExcluded `json:"excluded"`
	TaskStates    map[string]int      `json:"task_states"`
	ImportResults map[string]int      `json:"import_results"`
}

type EmpiricalExcluded struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Reason   string `json:"reason"`
	FromLine int    `json:"from_line"`
	ToLine   int    `json:"to_line"`
}

// FitEmpiricalTimings keeps a source's independently measured assembly and
// single-block import intervals. Exclusions remain explicit; an observed seal
// result never becomes proof of remote receipt or of request completion.
func FitEmpiricalTimings(in RuntimeObservation, from, to uint64, until time.Duration) (EmpiricalTimings, error) {
	out := EmpiricalTimings{Source: in.Source, Build: []AppSample{}, Import: []AppSample{}, Excluded: []EmpiricalExcluded{}, TaskStates: map[string]int{}, ImportResults: map[string]int{}}
	c := in.Capture
	if err := c.Validate(); err != nil {
		return out, err
	}
	if in.Source.ID == "" || in.Source.Kind != "runtime" || in.Source.Node != c.Node || in.Source.SHA256 != c.SourceSHA || !hexLength(in.Source.SHA256, 64) || !c.Complete || c.SequenceGaps != "0" || from == 0 || to < from || to-from >= 10000 || until <= 0 || until > 24*time.Hour {
		return out, errors.New("incomplete empirical timing source")
	}
	exclude := func(kind, id, reason string, a, b int) {
		out.Excluded = append(out.Excluded, EmpiricalExcluded{kind, id, reason, a, b})
	}
	appendSample := func(kind, id, definition, height, text string, a, b int) {
		if !empiricalHeightInRange(height, from, to) {
			exclude(kind, id, "height_outside_scope", a, b)
			return
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil || n < 0 || strconv.FormatInt(n, 10) != text || time.Duration(n) > until || a < 1 || b <= a || b > len(c.Points) {
			exclude(kind, id, "interval_unavailable", a, b)
			return
		}
		s := AppSample{BuildID: "runtime-" + id, Definition: definition, Nanoseconds: n, Input: in.Source.ID, Node: c.Node, Run: c.Run, FromLine: int64(a), ToLine: int64(b)}
		if kind == "build" {
			out.Build = append(out.Build, s)
		} else {
			out.Import = append(out.Import, s)
		}
	}
	seenTasks := map[string]bool{}
	for _, task := range c.Tasks {
		if seenTasks[task.ID] || task.ID == "" {
			return out, errors.New("duplicate empirical task")
		}
		seenTasks[task.ID] = true
		out.TaskStates[task.State]++
		if task.State != "observed_result" && task.State != "observed_cancellation" {
			exclude("build", task.ID, "task_interval_unavailable", task.StartLine, task.EndLine)
			continue
		}
		offers := []runtimeobs.Point{}
		for _, point := range task.Stages {
			if point.Line < 1 || point.Line > len(c.Points) || !reflect.DeepEqual(point, c.Points[point.Line-1]) || point.ID != task.ID || point.Type != "operation_stage" {
				return out, errors.New("empirical task source mismatch")
			}
			if point.Stage == "task_offer" {
				offers = append(offers, point)
			}
		}
		intervals := []runtimeobs.Interval{}
		for _, interval := range task.Intervals {
			if interval.Definition == "worker_entry_to_task_offer" {
				intervals = append(intervals, interval)
			}
		}
		if len(offers) != 1 || len(intervals) != 1 || intervals[0].ToLine != offers[0].Line {
			exclude("build", task.ID, "assembly_interval_ambiguous", task.StartLine, task.EndLine)
			continue
		}
		x := intervals[0]
		if x.FromLine != task.StartLine || x.FromLine < 1 || x.FromLine > len(c.Points) {
			return out, errors.New("empirical assembly source mismatch")
		}
		start := c.Points[x.FromLine-1]
		if start.Line != x.FromLine || start.Type != "operation_start" || start.Operation != "worker_commit_work" || start.ID != task.ID || !empiricalInterval(start, offers[0], x.Nanoseconds) {
			return out, errors.New("empirical assembly interval mismatch")
		}
		appendSample("build", task.ID, "runtime_worker_entry_to_task_offer", offers[0].Height, x.Nanoseconds, x.FromLine, x.ToLine)
	}
	seenCalls := map[string]bool{}
	for _, call := range c.Calls {
		if call.Operation != "write_block_and_set_head" && call.Operation != "insert_chain" {
			continue
		}
		if seenCalls[call.ID] || call.ID == "" {
			return out, errors.New("duplicate empirical import")
		}
		seenCalls[call.ID] = true
		out.ImportResults[call.Result]++
		if call.StartLine < 1 || call.EndLine > len(c.Points) || call.EndLine <= call.StartLine {
			exclude("import", call.ID, "interval_unavailable", call.StartLine, call.EndLine)
			continue
		}
		start, end := c.Points[call.StartLine-1], c.Points[call.EndLine-1]
		if start.Line != call.StartLine || end.Line != call.EndLine || start.Type != "operation_start" || end.Type != "operation_end" || start.ID != call.ID || end.ID != call.ID || start.Operation != call.Operation || end.Result != call.Result || !empiricalInterval(start, end, call.Nanoseconds) {
			return out, errors.New("empirical call source mismatch")
		}
		if call.Result != "ok" {
			exclude("import", call.ID, "not_successful", call.StartLine, call.EndLine)
			continue
		}
		if call.Operation == "insert_chain" && (start.Count != "1" || end.Index != "1") {
			exclude("import", call.ID, "not_single_block", call.StartLine, call.EndLine)
			continue
		}
		height := call.Height
		if height == "" {
			height = end.Height
		}
		if start.Height != "" && start.Height != height || end.Height != "" && end.Height != height {
			return out, errors.New("empirical import height mismatch")
		}
		if start.Hash != "" && end.Hash != "" && start.Hash != end.Hash || call.Hash != "" && end.Hash != "" && call.Hash != end.Hash {
			return out, errors.New("empirical import hash mismatch")
		}
		appendSample("import", call.ID, "runtime_"+call.Operation, height, call.Nanoseconds, call.StartLine, call.EndLine)
	}
	return out, nil
}

func empiricalInterval(a, b runtimeobs.Point, text string) bool {
	from, e1 := strconv.ParseInt(a.Mono, 10, 64)
	to, e2 := strconv.ParseInt(b.Mono, 10, 64)
	return e1 == nil && e2 == nil && from >= 0 && to >= from && a.Line > 0 && b.Line > a.Line && strconv.FormatInt(from, 10) == a.Mono && strconv.FormatInt(to, 10) == b.Mono && strconv.FormatInt(to-from, 10) == text
}

func empiricalHeightInRange(text string, from, to uint64) bool {
	if len(text) == 0 || len(text) > 1024 || strings.HasPrefix(text, "0") {
		return false
	}
	n, ok := new(big.Int).SetString(text, 10)
	if !ok || n.String() != text || n.Sign() <= 0 {
		return false
	}
	return n.Cmp(new(big.Int).SetUint64(from)) >= 0 && n.Cmp(new(big.Int).SetUint64(to)) <= 0
}
