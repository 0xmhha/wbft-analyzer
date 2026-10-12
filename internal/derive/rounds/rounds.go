// Package rounds derives log-correlated causes and per-node decision claims.
// A correlated cause is an observation with a source pointer, not a verdict.
package rounds

import (
	"math/big"
	"sort"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

type Bin struct {
	Node    string `json:"node"`
	Profile string `json:"profile"`
	Round   string `json:"round"`
	Count   int64  `json:"count"`
}
type Transition struct {
	Node       string `json:"node"`
	Profile    string `json:"profile"`
	Input      string `json:"input"`
	Line       int64  `json:"line"`
	Wall       string `json:"t_wall"`
	Height     string `json:"height"`
	Round      string `json:"round"`
	Proposer   string `json:"proposer"`
	Cause      string `json:"cause"`
	CauseInput string `json:"cause_input"`
	CauseLine  int64  `json:"cause_line"`
	Confidence string `json:"confidence"`
}
type Summary struct {
	Decisions          []Bin        `json:"decisions"`
	Entries            []Bin        `json:"entries"`
	Transitions        []Transition `json:"transitions"`
	TransitionsOmitted int64        `json:"transitions_omitted"`
	UnknownDecisions   int64        `json:"unknown_decisions"`
}
type trigger struct {
	e             logs.Event
	cause, target string
}

func Derive(events []logs.Event) Summary {
	out := Summary{Decisions: []Bin{}, Entries: []Bin{}, Transitions: []Transition{}}
	pending := map[[2]string]trigger{}
	claims := map[[2]string]logs.Event{}
	bins := map[[3]string]int64{}
	for _, e := range events {
		rec := e.Record
		key := [2]string{e.Node, e.Run}
		switch rec.Kind {
		case event.EngineStart, event.EngineStop:
			delete(pending, key)
		case event.TimerFire:
			if rec.View != nil {
				r, ok := new(big.Int).SetString(rec.View.Round, 10)
				if ok {
					r.Add(r, big.NewInt(1))
					pending[key] = trigger{e, event.CauseTimeout, r.String()}
				}
			}
		case event.Quorum:
			if rec.Fields["what"] == "F_PLUS_ONE" && rec.View != nil {
				pending[key] = trigger{e, event.CauseFPlusOne, ""}
			}
		case event.RoundEnter:
			if rec.View == nil || rec.View.Round == "" {
				delete(pending, key)
				continue
			}
			v := rec.View
			bins[[3]string{e.Node, e.Profile, v.Round}]++
			t := Transition{Node: e.Node, Profile: e.Profile, Input: e.Input, Line: e.Line, Wall: e.Wall, Height: v.Seq, Round: v.Round, Cause: "unknown", Confidence: "unknown"}
			t.Proposer, _ = rec.Fields["next.proposer"].(string)
			if cause, ok := rec.Fields["cause"].(string); ok {
				t.Cause = cause
				t.CauseInput = e.Input
				t.CauseLine = e.Line
				t.Confidence = "recorded"
			}
			if p, ok := pending[key]; ok && p.e.Record.View.Seq == v.Seq && p.e.Line < e.Line && !wallBefore(e.Wall, p.e.Wall) && (p.target == "" || p.target == v.Round) {
				before, bok := new(big.Int).SetString(p.e.Record.View.Round, 10)
				after, aok := new(big.Int).SetString(v.Round, 10)
				if bok && aok && after.Cmp(before) > 0 {
					t.Cause = p.cause
					t.CauseInput = p.e.Input
					t.CauseLine = p.e.Line
					t.Confidence = "log_correlated"
				}
			}
			delete(pending, key)
			if len(out.Transitions) < 1000 {
				out.Transitions = append(out.Transitions, t)
			} else {
				out.TransitionsOmitted++
			}
		case event.NewHead:
			if rec.View != nil && rec.View.Seq != "" {
				k := [2]string{e.Node, rec.View.Seq}
				if old, ok := claims[k]; !ok || wallBefore(old.Wall, e.Wall) {
					claims[k] = e
				}
			}
		}
	}
	for k, count := range bins {
		out.Entries = append(out.Entries, Bin{k[0], k[1], k[2], count})
	}
	decided := map[[3]string]int64{}
	for _, e := range claims {
		r := e.Record.View.Round
		if r == "" {
			out.UnknownDecisions++
		} else {
			decided[[3]string{e.Node, e.Profile, r}]++
		}
	}
	for k, count := range decided {
		out.Decisions = append(out.Decisions, Bin{k[0], k[1], k[2], count})
	}
	sortBins(out.Entries)
	sortBins(out.Decisions)
	sort.Slice(out.Transitions, func(i, j int) bool {
		a, b := out.Transitions[i], out.Transitions[j]
		if a.Wall != b.Wall {
			return wallBefore(a.Wall, b.Wall)
		}
		if a.Input != b.Input {
			return a.Input < b.Input
		}
		return a.Line < b.Line
	})
	return out
}
func sortBins(xs []Bin) {
	sort.Slice(xs, func(i, j int) bool {
		a, b := xs[i], xs[j]
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		x, _ := new(big.Int).SetString(a.Round, 10)
		y, _ := new(big.Int).SetString(b.Round, 10)
		return x.Cmp(y) < 0
	})
}

func wallBefore(a, b string) bool {
	x, e1 := time.Parse(time.RFC3339Nano, a)
	y, e2 := time.Parse(time.RFC3339Nano, b)
	return e1 == nil && e2 == nil && x.Before(y)
}
