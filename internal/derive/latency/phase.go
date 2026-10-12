// Package latency derives phase measurements, not consensus verdicts.
package latency

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

var Metrics = []string{"preprepare", "prepare_quorum", "commit_quorum", "commit", "import", "round_to_decision", "round_to_import"}
var boundaries = [][2]string{{"round", "proposal"}, {"proposal", "prepare"}, {"prepare", "commit_quorum"}, {"commit_quorum", "decision"}, {"decision", "import"}, {"round", "decision"}, {"round", "import"}}

type Source struct {
	Input        string  `json:"input"`
	Line         int64   `json:"line"`
	Wall         string  `json:"t_wall"`
	Mono         *string `json:"t_mono_ns"`
	ViewInferred bool    `json:"view_inferred"`
}
type Sample struct {
	ID         string   `json:"id"`
	Node       string   `json:"node"`
	Profile    string   `json:"profile"`
	Run        string   `json:"run"`
	Height     string   `json:"height"`
	Round      string   `json:"round"`
	Metric     string   `json:"metric"`
	Clock      string   `json:"clock"`
	Status     string   `json:"status"`
	Seconds    *float64 `json:"seconds"`
	Start      *Source  `json:"start"`
	End        *Source  `json:"end"`
	At         string   `json:"at"`
	Duplicates int64    `json:"duplicate_markers"`
}
type Filter struct {
	From, To                    time.Time
	Node, Height, Round, Metric string
}
type attempt struct {
	node, profile, run, height, round, id string
	marks                                 map[string]*logs.Event
	duplicates                            int64
	at                                    string
}

// Derive consumes each input in original line order. Anchors cannot cross
// node, input, engine run, height or round. A new round closes its predecessor.
func Derive(events []logs.Event, f Filter) []Sample {
	attempts := []*attempt{}
	active := map[[2]string]*attempt{}
	for i := range events {
		e := &events[i]
		key := [2]string{e.Node, e.Input}
		if e.Record.Kind == event.EngineStart || e.Record.Kind == event.EngineStop {
			delete(active, key)
			continue
		}
		h, r := "", ""
		if e.Record.View != nil {
			h, r = e.Record.View.Seq, e.Record.View.Round
		}
		if e.Record.Kind == event.NewHead || e.Record.Kind == event.FinalizeHandover {
			if h == "" {
				h = str(e.Record.Fields["number"])
			}
			if r == "" {
				r = str(e.Record.Fields["round"])
			}
		}
		if h == "" || r == "" {
			continue
		}
		marker := ""
		legacy := strings.HasPrefix(e.Profile, "gstable@")
		if !legacy && !strings.HasPrefix(e.Profile, "wbft@") {
			continue
		}
		switch e.Record.Kind {
		case event.RoundEnter:
			marker = "round"
		case event.PreprepareAccept:
			marker = "proposal"
		case event.Quorum:
			if e.Record.Fields["what"] == "PREPARE" {
				marker = "prepare"
			}
			if e.Record.Fields["what"] == "COMMIT" {
				marker = "commit_quorum"
			}
		case event.FinalizeHandover:
			if !legacy {
				marker = "decision"
			}
		case event.NewHead:
			if legacy {
				marker = "decision"
			} else {
				marker = "import"
			}
		}
		if marker == "" {
			continue
		}
		a := active[key]
		if marker == "round" || a == nil || a.run != e.Run || a.height != h || a.round != r {
			a = &attempt{node: e.Node, profile: e.Profile, run: e.Run, height: h, round: r, id: fmt.Sprintf("%s:%d", e.Input, e.Line), marks: map[string]*logs.Event{}}
			attempts = append(attempts, a)
			active[key] = a
		}
		if a.marks[marker] != nil {
			a.duplicates++
		} else {
			a.marks[marker] = e
		}
		if a.at == "" || before(a.at, e.Wall) {
			a.at = e.Wall
		}
	}
	out := []Sample{}
	for _, a := range attempts {
		if f.Node != "" && f.Node != a.node || f.Height != "" && f.Height != a.height || f.Round != "" && f.Round != a.round {
			continue
		}
		for i, metric := range Metrics {
			if f.Metric != "" && f.Metric != metric {
				continue
			}
			start, end := a.marks[boundaries[i][0]], a.marks[boundaries[i][1]]
			s := Sample{ID: a.id + ":" + metric, Node: a.node, Profile: a.profile, Run: a.run, Height: a.height, Round: a.round, Metric: metric, Clock: "unavailable", Status: "missing_both", At: a.at, Duplicates: a.duplicates}
			if start != nil && start.Mono != nil || end != nil && end.Mono != nil {
				s.Clock = "monotonic"
			} else if start != nil || end != nil {
				s.Clock = "wall"
			}
			if start != nil {
				s.Start = source(start)
			}
			if end != nil {
				s.End = source(end)
				s.At = end.Wall
			} else if start != nil {
				s.At = start.Wall
			}
			at, err := time.Parse(time.RFC3339Nano, s.At)
			if err != nil {
				continue
			}
			if !f.From.IsZero() && at.Before(f.From) || !f.To.IsZero() && at.After(f.To) {
				continue
			}
			switch {
			case start == nil && end == nil:
			case start == nil:
				s.Status = "missing_start"
			case end == nil:
				s.Status = "missing_end"
			default:
				s.Clock, s.Status, s.Seconds = elapsed(start, end)
			}
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.At != b.At {
			return before(a.At, b.At)
		}
		return a.ID < b.ID
	})
	return out
}
func str(v any) string { s, _ := v.(string); return s }
func source(e *logs.Event) *Source {
	return &Source{Input: e.Input, Line: e.Line, Wall: e.Wall, Mono: e.Mono, ViewInferred: e.ViewInferred}
}
func before(a, b string) bool {
	x, _ := time.Parse(time.RFC3339Nano, a)
	y, _ := time.Parse(time.RFC3339Nano, b)
	return x.Before(y)
}
func elapsed(a, b *logs.Event) (string, string, *float64) {
	clock := "wall"
	var sec float64
	if a.Mono != nil || b.Mono != nil {
		clock = "monotonic"
		if a.Mono == nil || b.Mono == nil {
			return clock, "missing_clock", nil
		}
		x, ok1 := new(big.Int).SetString(*a.Mono, 10)
		y, ok2 := new(big.Int).SetString(*b.Mono, 10)
		if !ok1 || !ok2 || x.Sign() < 0 || y.Sign() < 0 || !x.IsInt64() || !y.IsInt64() {
			return clock, "invalid_clock", nil
		}
		delta := new(big.Int).Sub(y, x)
		v, _ := new(big.Float).SetInt(delta).Float64()
		sec = v / 1e9
	} else {
		x, e1 := time.Parse(time.RFC3339Nano, a.Wall)
		y, e2 := time.Parse(time.RFC3339Nano, b.Wall)
		if e1 != nil || e2 != nil {
			return clock, "invalid_clock", nil
		}
		sec = y.Sub(x).Seconds()
	}
	if math.IsNaN(sec) || math.IsInf(sec, 0) {
		return clock, "invalid_clock", nil
	}
	if sec < 0 {
		return clock, "negative", &sec
	}
	return clock, "valid", &sec
}
