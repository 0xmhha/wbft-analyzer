package scenario

import (
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

// AppOutcome preserves a known return path independently of successful timing
// samples. Known cancellations/failures do not become simulator defaults.
type AppOutcome struct {
	BuildID      string `json:"build_id"`
	Status       string `json:"status"`
	Input        string `json:"input"`
	Node         string `json:"node"`
	Run          string `json:"run"`
	HandoverLine int64  `json:"handover_line"`
	StartLine    int64  `json:"start_line,omitempty"`
	EndLine      int64  `json:"end_line"`
}
type buildScope struct{ node, input, run string }

func scopeOf(x logs.Event) buildScope { return buildScope{x.Node, x.Input, x.Run} }
func buildScopes(xs []logs.Event) map[buildScope]bool {
	out := map[buildScope]bool{}
	for _, x := range xs {
		if x.Record.Kind == event.BuildHandover || x.Record.Kind == event.BuildStarted || x.Record.Kind == event.BuildFinished {
			out[scopeOf(x)] = true
		}
	}
	return out
}

type lifecycleKey struct {
	scope buildScope
	id    string
}
type lifecycle struct{ handover, start, end []logs.Event }

func validBuildID(s string) bool {
	if !strings.HasPrefix(s, "build-") || len(s) > 26 {
		return false
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "build-"), 10, 64)
	return err == nil && n > 0 && s == "build-"+strconv.FormatUint(n, 10)
}
func sameBuildView(a, b logs.Event) bool {
	av, bv := a.Record.View, b.Record.View
	if av == nil || bv == nil || av.Seq == "" || av.Round == "" || av.Seq != bv.Seq || av.Round != bv.Round {
		return false
	}
	an, _ := a.Record.Fields["number"].(string)
	bn, _ := b.Record.Fields["number"].(string)
	return an == av.Seq && bn == bv.Seq
}
func fitBuildLifecycles(xs []logs.Event, modern map[buildScope]bool, out *AppTiming) {
	type viewKey struct {
		scope         buildScope
		height, round string
	}
	requests, handovers := map[viewKey]int{}, map[viewKey]int{}
	for _, x := range xs {
		if !modern[scopeOf(x)] || x.Record.Kind != event.BuildRequest && x.Record.Kind != event.BuildHandover {
			continue
		}
		if x.Record.View == nil {
			out.Unproved++
			continue
		}
		k := viewKey{scopeOf(x), x.Record.View.Seq, x.Record.View.Round}
		if x.Record.Kind == event.BuildRequest {
			requests[k]++
		} else {
			handovers[k]++
		}
	}
	for k, n := range requests {
		if handovers[k] != n {
			out.Unproved++
		}
	}
	groups := map[lifecycleKey]*lifecycle{}
	order := []lifecycleKey{}
	for _, x := range xs {
		if !modern[scopeOf(x)] {
			continue
		}
		kind := x.Record.Kind
		if kind != event.BuildHandover && kind != event.BuildStarted && kind != event.BuildFinished {
			continue
		}
		id, _ := x.Record.Fields["build_id"].(string)
		if !validBuildID(id) {
			out.Unproved++
			continue
		}
		key := lifecycleKey{scopeOf(x), id}
		group := groups[key]
		if group == nil {
			group = &lifecycle{}
			groups[key] = group
			order = append(order, key)
		}
		switch kind {
		case event.BuildHandover:
			group.handover = append(group.handover, x)
		case event.BuildStarted:
			group.start = append(group.start, x)
		case event.BuildFinished:
			group.end = append(group.end, x)
		}
	}
	for _, key := range order {
		group := groups[key]
		if len(group.handover) != 1 || len(group.end) != 1 || len(group.start) > 1 {
			out.Unproved++
			continue
		}
		h, f := group.handover[0], group.end[0]
		if !sameBuildView(h, f) || h.Line < 1 || f.Line <= h.Line {
			out.Unproved++
			continue
		}
		if _, err := localElapsed(h, f); err != nil {
			out.Unproved++
			continue
		}
		wait, _ := h.Record.Fields["wait_ns"].(string)
		if n, err := strconv.ParseInt(wait, 10, 64); err != nil || n < 0 {
			out.Unproved++
			continue
		}
		status, _ := f.Record.Fields["status"].(string)
		outcome := AppOutcome{BuildID: key.id, Status: status, Input: h.Input, Node: h.Node, Run: h.Run, HandoverLine: h.Line, EndLine: f.Line}
		var elapsed int64
		if len(group.start) == 1 {
			s := group.start[0]
			delta, err := localElapsed(s, f)
			_, fromErr := localElapsed(h, s)
			if !sameBuildView(h, s) || s.Line <= h.Line || f.Line <= s.Line || err != nil || fromErr != nil {
				out.Unproved++
				continue
			}
			elapsed = int64(delta)
			outcome.StartLine = s.Line
		}
		switch status {
		case "submitted":
			hash, _ := f.Record.Fields["hash"].(string)
			if len(group.start) != 1 || !strings.HasPrefix(hash, "0x") || !hexLength(strings.TrimPrefix(hash, "0x"), 64) {
				out.Unproved++
				continue
			}
			out.Build = append(out.Build, AppSample{BuildID: key.id, Definition: "assembly_to_submission", Nanoseconds: elapsed, Input: h.Input, Node: h.Node, Run: h.Run, FromLine: outcome.StartLine, ToLine: f.Line})
		case "replaced", "height_left", "stopped", "unavailable", "head_changed", "failed":
			// A return path alone does not establish the required queue, availability,
			// executor failure or cancellation inputs. Keep it outside successful timing.
			out.Unsupported++
		default:
			out.Unproved++
			continue
		}
		out.Outcomes = append(out.Outcomes, outcome)
	}
}
