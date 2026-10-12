// Package replay projects recorded facts; it does not execute consensus rules.
package replay

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

type Pointer struct {
	Input string `json:"input"`
	Line  int64  `json:"line"`
	Wall  string `json:"t_wall"`
}
type Timer struct {
	Kind         string   `json:"kind"`
	Engine       string   `json:"engine"`
	Generation   string   `json:"generation"`
	Status       string   `json:"status"`
	DeadlineMono string   `json:"deadline_mono_ns"`
	DurationMS   string   `json:"duration_ms"`
	Source       Pointer  `json:"source"`
	Closed       *Pointer `json:"closed"`
}
type Counter struct {
	Count  string  `json:"count"`
	Quorum string  `json:"quorum"`
	Source Pointer `json:"source"`
}
type State struct {
	Node                 string             `json:"node"`
	Run                  string             `json:"run"`
	Profile              string             `json:"profile"`
	Online               *bool              `json:"online"`
	EngineActive         *bool              `json:"engine_active"`
	View                 *event.View        `json:"view"`
	Cause                string             `json:"cause"`
	ConsensusState       string             `json:"state"`
	StateSource          *Pointer           `json:"state_source"`
	Counters             map[string]Counter `json:"counters"`
	Timers               map[string]Timer   `json:"timers"`
	Backlog              *int64             `json:"backlog"`
	BacklogPartial       bool               `json:"backlog_partial"`
	LastHead             string             `json:"last_head"`
	HeadKind             string             `json:"head_kind"`
	Latest               *Pointer           `json:"latest"`
	UnmatchedTimerEvents int64              `json:"unmatched_timer_events"`
}
type Keyframe struct {
	At     string `json:"at"`
	Input  string `json:"input"`
	Line   int64  `json:"line"`
	Folded int64  `json:"folded"`
	State  State  `json:"state"`
}

func New(node string) State {
	return State{Node: node, Counters: map[string]Counter{}, Timers: map[string]Timer{}}
}
func (s *State) resetTransient() {
	s.View = nil
	s.ConsensusState = ""
	s.StateSource = nil
	s.Cause = ""
	s.Counters = map[string]Counter{}
	s.Timers = map[string]Timer{}
	s.Backlog = nil
	s.BacklogPartial = true
}
func text(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return string(x)
	}
	return ""
}
func boolean(v bool) *bool         { return &v }
func pointer(e logs.Event) Pointer { return Pointer{e.Input, e.Line, e.Wall} }

// Apply updates only facts carried by the record. Message views never replace
// the node view; only ROUND_ENTER establishes the current view. Missing state,
// timer generations and backlog prefixes remain unknown or partial.
func Apply(s *State, e logs.Event) {
	p := pointer(e)
	f := e.Record.Fields
	if s.Run != "" && s.Run != e.Run {
		s.resetTransient()
		s.Online = nil
		s.EngineActive = nil
		s.LastHead = ""
		s.HeadKind = ""
	}
	s.Run = e.Run
	s.Profile = e.Profile
	s.Latest = &p
	switch e.Record.Kind {
	case event.NodeStart:
		s.resetTransient()
		s.Online = boolean(true)
	case event.NodeStop:
		s.Online = boolean(false)
		s.EngineActive = boolean(false)
		s.resetTransient()
	case event.EngineStart:
		s.resetTransient()
		s.EngineActive = boolean(true)
	case event.EngineStop:
		s.EngineActive = boolean(false)
		s.resetTransient()
	case event.RoundEnter:
		if e.Record.View != nil {
			v := *e.Record.View
			s.View = &v
			s.Counters = map[string]Counter{}
			s.ConsensusState = ""
			s.StateSource = nil
			s.Cause = text(f["cause"])
		}
	case event.StateChange:
		if e.Record.View != nil && (s.View == nil || *e.Record.View != *s.View) {
			return
		}
		state := text(f["to"])
		if state == "" {
			state = text(f["new.state"])
		}
		if state != "" {
			s.ConsensusState = state
			s.StateSource = &p
		}
	case event.Quorum:
		if e.Record.View != nil && (s.View == nil || *e.Record.View != *s.View) {
			return
		}
		what := text(f["what"])
		count := text(f["count"])
		if count == "" {
			switch what {
			case "PREPARE":
				count = text(f["prepares.count"])
			case "COMMIT":
				count = text(f["commits.count"])
			case "F_PLUS_ONE":
				count = text(f["higherRoundChanges.count"])
			case "ROUND_CHANGE":
				count = text(f["currentRoundChanges.count"])
			}
		}
		if what != "" {
			s.Counters[what] = Counter{count, text(f["quorum"]), p}
		}
	case event.TimerArm:
		kind := text(f["timer"])
		if kind != "" {
			s.Timers[kind] = Timer{kind, text(f["engine_run"]), text(f["gen"]), "armed", text(f["deadline_mono_ns"]), text(f["duration_ms"]), p, nil}
		}
	case event.TimerCancel, event.TimerFire:
		kind := text(f["timer"])
		t, ok := s.Timers[kind]
		// A stale expiration cannot remove a currently armed generation.
		if stale, _ := f["stale"].(bool); stale {
			return
		}
		if !ok || (t.Generation != "" && text(f["gen"]) != t.Generation) || (t.Engine != "" && text(f["engine_run"]) != t.Engine) {
			s.UnmatchedTimerEvents++
			return
		}
		if e.Record.Kind == event.TimerCancel {
			t.Status = "cancelled"
		} else {
			t.Status = "fired"
		}
		t.Closed = &p
		s.Timers[kind] = t
	case event.Backlog:
		if n, err := strconv.ParseInt(text(f["backlogs_size"]), 10, 64); err == nil && n >= 0 {
			s.Backlog = &n
			s.BacklogPartial = false
			return
		}
		if s.Backlog == nil {
			zero := int64(0)
			s.Backlog = &zero
			s.BacklogPartial = true
		}
		switch text(f["op"]) {
		case "push":
			*s.Backlog = *s.Backlog + 1
		case "pop", "drop":
			if *s.Backlog > 0 {
				*s.Backlog = *s.Backlog - 1
			} else {
				s.BacklogPartial = true
			}
		}
	case event.NewHead:
		if n := text(f["number"]); n != "" {
			s.LastHead = n
			if e.Record.Src == "event" || strings.HasPrefix(e.Profile, "wbft@") {
				s.HeadKind = "imported_head"
			} else {
				s.HeadKind = "decision_claim"
			}
		}
	}
}

// Clone returns an independent snapshot.
func Clone(s State) State {
	b, _ := json.Marshal(s)
	var out State
	_ = json.Unmarshal(b, &out)
	return out
}

// Ordered is the visual wall-time axis. Original input/line breaks equal-time
// ties deterministically. It does not imply a cross-node causal order.
func Ordered(events []logs.Event) []logs.Event {
	out := append([]logs.Event(nil), events...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ta, _ := time.Parse(time.RFC3339Nano, a.Wall)
		tb, _ := time.Parse(time.RFC3339Nano, b.Wall)
		if !ta.Equal(tb) {
			return ta.Before(tb)
		}
		if a.Input != b.Input {
			return a.Input < b.Input
		}
		return a.Line < b.Line
	})
	return out
}

// Build snapshots height boundaries and every 1024 records per node. Each
// snapshot is after its source record and owns its maps/pointers.
func Build(events []logs.Event) []Keyframe {
	states := map[string]State{}
	counts := map[string]int64{}
	out := []Keyframe{}
	for _, e := range Ordered(events) {
		s, ok := states[e.Node]
		if !ok {
			s = New(e.Node)
		}
		oldHeight := ""
		if s.View != nil {
			oldHeight = s.View.Seq
		}
		Apply(&s, e)
		counts[e.Node]++
		states[e.Node] = s
		heightChanged := s.View != nil && s.View.Seq != oldHeight
		if counts[e.Node] == 1 || counts[e.Node]%1024 == 0 || heightChanged || e.Record.Kind == event.EngineStart || e.Record.Kind == event.EngineStop || e.Record.Kind == event.NodeStart || e.Record.Kind == event.NodeStop {
			out = append(out, Keyframe{e.Wall, e.Input, e.Line, counts[e.Node], Clone(s)})
		}
	}
	return out
}

// Seek folds only records after the nearest preceding keyframe. Its position
// includes input/line so equal timestamps cannot repeat or omit source records.
func Seek(events []logs.Event, frames []Keyframe, node string, target time.Time) (State, int64) {
	state := New(node)
	var frame *Keyframe
	for i := range frames {
		candidate := &frames[i]
		at, _ := time.Parse(time.RFC3339Nano, candidate.At)
		if candidate.State.Node == node && !at.After(target) {
			frame = candidate
		}
	}
	if frame != nil {
		state = Clone(frame.State)
	}
	applied := int64(0)
	for _, e := range Ordered(events) {
		if e.Node != node {
			continue
		}
		at, _ := time.Parse(time.RFC3339Nano, e.Wall)
		if at.After(target) {
			continue
		}
		if frame != nil {
			ft, _ := time.Parse(time.RFC3339Nano, frame.At)
			if at.Before(ft) || at.Equal(ft) && (e.Input < frame.Input || e.Input == frame.Input && e.Line <= frame.Line) {
				continue
			}
		}
		Apply(&state, e)
		applied++
	}
	return state, applied
}
