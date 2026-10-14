package scenario

import (
	"errors"
	"strconv"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

type AppSample struct {
	Nanoseconds int64  `json:"nanoseconds"`
	Input       string `json:"input"`
	Node        string `json:"node"`
	Run         string `json:"run"`
	FromLine    int64  `json:"from_line"`
	ToLine      int64  `json:"to_line"`
}

type AppTiming struct {
	Build    []AppSample `json:"build"`
	Import   []AppSample `json:"import"`
	Unproved int64       `json:"unproved"`
}

// FitAppTiming subtracts the declared minimum build wait from assembly time.
// Multiple build requests for one height are ambiguous without a request ID.
func FitAppTiming(xs []logs.Event) (AppTiming, error) {
	out := AppTiming{Build: []AppSample{}, Import: []AppSample{}}
	type key struct{ node, input, run, height string }
	requests := map[key][]logs.Event{}
	for _, x := range xs {
		if x.Profile != logs.EventProfile {
			return out, errors.New("native application timing required")
		}
		kind := x.Record.Kind
		if kind == event.BuildRequest {
			if x.Record.View == nil {
				out.Unproved++
				continue
			}
			k := key{x.Node, x.Input, x.Run, x.Record.View.Seq}
			requests[k] = append(requests[k], x)
		}
		if kind == event.ProposalSubmitted {
			height, _ := x.Record.Fields["number"].(string)
			k := key{x.Node, x.Input, x.Run, height}
			rs := requests[k]
			if height == "" || len(rs) != 1 {
				out.Unproved++
				continue
			}
			request := rs[0]
			delete(requests, k)
			elapsed, err := localElapsed(request, x)
			waitText, _ := request.Record.Fields["wait_ms"].(string)
			wait, parse := strconv.ParseInt(waitText, 10, 64)
			if err != nil || parse != nil || wait < 0 || wait > 3600000 || elapsed < time.Duration(wait)*time.Millisecond {
				out.Unproved++
				continue
			}
			out.Build = append(out.Build, AppSample{Nanoseconds: int64(elapsed - time.Duration(wait)*time.Millisecond), Input: x.Input, Node: x.Node, Run: x.Run, FromLine: request.Line, ToLine: x.Line})
		}
		if kind == event.CommitResult {
			text, _ := x.Record.Fields["duration_ms"].(string)
			duration, err := strconv.ParseInt(text, 10, 64)
			ok, known := x.Record.Fields["ok"].(bool)
			if err != nil || duration < 0 || duration > 3600000 || !known || !ok {
				out.Unproved++
				continue
			}
			out.Import = append(out.Import, AppSample{Nanoseconds: int64(time.Duration(duration) * time.Millisecond), Input: x.Input, Node: x.Node, Run: x.Run, FromLine: x.Line, ToLine: x.Line})
		}
	}
	for _, rs := range requests {
		out.Unproved += int64(len(rs))
	}
	return out, nil
}

func localElapsed(a, b logs.Event) (time.Duration, error) {
	if a.Mono == nil || b.Mono == nil {
		return 0, errors.New("application monotonic clock unavailable")
	}
	x, e1 := strconv.ParseInt(*a.Mono, 10, 64)
	y, e2 := strconv.ParseInt(*b.Mono, 10, 64)
	if e1 != nil || e2 != nil || x < 0 || y < x {
		return 0, errors.New("application clock invalid")
	}
	return time.Duration(y - x), nil
}
