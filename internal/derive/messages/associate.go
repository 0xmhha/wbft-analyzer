package messages

import (
	"encoding/hex"
	"encoding/json"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
	"sort"
	"strconv"
	"strings"
	"time"
)

type AssociationProof struct {
	Status             string              `json:"status"`
	JournalOnlyRuns    int64               `json:"journal_only_runs"`
	EventOnlyRuns      int64               `json:"event_only_runs"`
	SharedRuns         int64               `json:"shared_runs"`
	UnanchoredRuns     int64               `json:"unanchored_runs"`
	MatchedAnchors     int64               `json:"matched_anchors"`
	MissingAnchors     int64               `json:"missing_anchors"`
	ConflictingAnchors int64               `json:"conflicting_anchors"`
	Anchors            []AssociationAnchor `json:"anchors"`
}
type AssociationAnchor struct {
	ClockBasis string   `json:"clock_basis"`
	Node       string   `json:"node"`
	Run        string   `json:"run"`
	Step       string   `json:"step"`
	Status     string   `json:"status"`
	Journal    []Source `json:"journal"`
	Events     []Source `json:"events"`
}
type outcomeAnchor struct {
	signatures []string
	pointers   []Source
	wall, mono string
	clocks     int
}
type anchorKey struct{ node, run, step string }

func canonicalNode(n string) string {
	if len(n) == 42 && strings.HasPrefix(n, "0x") {
		if _, e := hex.DecodeString(n[2:]); e == nil {
			return strings.ToLower(n)
		}
	}
	return n
}

// VerifyAssociation compares complete stepped-outcome multisets and their
// recorded step clocks, not names or overlapping wall windows. Simulator
// seeds can reuse node/run IDs across different scenarios. Missing anchors
// do not prove identity, and a contradictory anchor refuses the association.
func VerifyAssociation(records []source.Record, events []logs.Event) AssociationProof {
	j, e := map[anchorKey]*outcomeAnchor{}, map[anchorKey]*outcomeAnchor{}
	jruns, eruns := map[[2]string]bool{}, map[[2]string]bool{}
	ensure := func(m map[anchorKey]*outcomeAnchor, k anchorKey) *outcomeAnchor {
		if m[k] == nil {
			m[k] = &outcomeAnchor{pointers: []Source{}, signatures: []string{}}
		}
		return m[k]
	}
	signature := func(key, phase, outcome string) string {
		b, _ := json.Marshal([]string{key, phase, outcome})
		return string(b)
	}
	for _, r := range records {
		n := canonicalNode(r.Node)
		jruns[[2]string{n, r.Run}] = true
		if r.Step == "" {
			continue
		}
		k := anchorKey{n, r.Run, r.Step}
		a := ensure(j, k)
		if r.Type == "outcome" && r.Key != "" {
			a.signatures = append(a.signatures, signature(r.Key, r.Phase, r.Outcome))
			a.pointers = append(a.pointers, recordSource(r))
		}
		if r.Type == "step" {
			a.clocks++
			a.wall = r.Wall
			if r.Mono != nil {
				a.mono = *r.Mono
			}
			a.pointers = append(a.pointers, recordSource(r))
		}
	}
	for _, r := range events {
		if r.Record.Src != "event" {
			continue
		}
		n := canonicalNode(r.Node)
		eruns[[2]string{n, r.Run}] = true
		if r.Record.Kind != event.MsgOutcome || value(r, "step") == "" || value(r, "dedup_key") == "" {
			continue
		}
		k := anchorKey{n, r.Run, value(r, "step")}
		a := ensure(e, k)
		a.signatures = append(a.signatures, signature(value(r, "dedup_key"), eventPhase(r), value(r, "outcome")))
		a.pointers = append(a.pointers, eventSource(r))
		mono := ""
		if r.Mono != nil {
			mono = *r.Mono
		}
		if a.clocks == 0 {
			a.wall = r.Wall
			a.mono = mono
			a.clocks = 1
		} else if a.wall != r.Wall || a.mono != mono {
			a.clocks++
		}
	}
	previous := map[anchorKey]*outcomeAnchor{}
	perRun := map[[2]string][]anchorKey{}
	for k, a := range j {
		if a.clocks > 0 {
			perRun[[2]string{k.node, k.run}] = append(perRun[[2]string{k.node, k.run}], k)
		}
	}
	for _, ks := range perRun {
		sort.Slice(ks, func(i, j int) bool {
			a, _ := strconv.ParseUint(ks[i].step, 10, 64)
			b, _ := strconv.ParseUint(ks[j].step, 10, 64)
			return a < b
		})
		for i := 1; i < len(ks); i++ {
			previous[ks[i]] = j[ks[i-1]]
		}
	}
	out := AssociationProof{Status: "insufficient", Anchors: []AssociationAnchor{}}
	shared := map[[2]string]bool{}
	for k := range jruns {
		if eruns[k] {
			shared[k] = true
			out.SharedRuns++
		}
	}
	out.JournalOnlyRuns = int64(len(jruns)) - out.SharedRuns
	out.EventOnlyRuns = int64(len(eruns)) - out.SharedRuns
	keys := map[anchorKey]bool{}
	for k, a := range j {
		if shared[[2]string{k.node, k.run}] && len(a.signatures) > 0 {
			keys[k] = true
		}
	}
	for k := range e {
		if shared[[2]string{k.node, k.run}] {
			keys[k] = true
		}
	}
	ordered := []anchorKey{}
	anchored := map[[2]string]bool{}
	for k := range keys {
		ordered = append(ordered, k)
		anchored[[2]string{k.node, k.run}] = true
	}
	for k := range shared {
		if !anchored[k] {
			out.UnanchoredRuns++
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.node != b.node {
			return a.node < b.node
		}
		if a.run != b.run {
			return a.run < b.run
		}
		return a.step < b.step
	})
	for _, k := range ordered {
		a, b := j[k], e[k]
		x := AssociationAnchor{Node: k.node, Run: k.run, Step: k.step, Status: "missing", Journal: []Source{}, Events: []Source{}}
		if a != nil {
			x.Journal = a.pointers
		}
		if b != nil {
			x.Events = b.pointers
		}
		if a == nil || b == nil || a.clocks == 0 || b.clocks == 0 || a.mono == "" || b.mono == "" {
			out.MissingAnchors++
		} else {
			sort.Strings(a.signatures)
			sort.Strings(b.signatures)
			aa, _ := json.Marshal(a.signatures)
			bb, _ := json.Marshal(b.signatures)
			clockOK := a.wall == b.wall && a.mono == b.mono
			if clockOK {
				x.ClockBasis = "exact_stamp"
			} else if withinCompletedStep(previous[k], a, b) {
				clockOK = true
				x.ClockBasis = "completed_step_interval"
				x.Journal = append(append([]Source(nil), x.Journal...), previous[k].pointers...)
			}
			if string(aa) != string(bb) || a.clocks != 1 || b.clocks != 1 || !clockOK {
				x.Status = "conflict"
				out.ConflictingAnchors++
			} else {
				x.Status = "matched"
				out.MatchedAnchors++
			}
		}
		out.Anchors = append(out.Anchors, x)
	}
	if out.ConflictingAnchors > 0 {
		out.Status = "conflict"
	} else if out.MatchedAnchors > 0 && out.MissingAnchors == 0 && out.UnanchoredRuns == 0 {
		out.Status = "matched"
	} else if out.MatchedAnchors > 0 {
		out.Status = "partial"
	}
	return out
}

// AssociatedSources limits mixed projection to runs whose stepped outcomes
// have been verified. Unshared runs remain in source coverage, not latency.
func AssociatedSources(records []source.Record, events []logs.Event, proof AssociationProof) ([]source.Record, []logs.Event) {
	allow := map[[2]string]bool{}
	if proof.Status == "matched" {
		for _, a := range proof.Anchors {
			if a.Status == "matched" {
				allow[[2]string{a.Node, a.Run}] = true
			}
		}
	}
	rs := []source.Record{}
	es := []logs.Event{}
	for _, r := range records {
		if allow[[2]string{canonicalNode(r.Node), r.Run}] {
			rs = append(rs, r)
		}
	}
	for _, e := range events {
		if allow[[2]string{canonicalNode(e.Node), e.Run}] && e.Record.Src == "event" {
			es = append(es, e)
		}
	}
	return rs, es
}

// Native runners stamp events at step entry and journal the step after handling
// its outputs. Both clocks must lie within adjacent recorded completion stamps;
// this is a source boundary proof, never a tolerance or timestamp correction.
func withinCompletedStep(previous, end, at *outcomeAnchor) bool {
	if previous == nil || previous.clocks != 1 || end.clocks != 1 || at.clocks != 1 {
		return false
	}
	lo, e1 := strconv.ParseInt(previous.mono, 10, 64)
	hi, e2 := strconv.ParseInt(end.mono, 10, 64)
	v, e3 := strconv.ParseInt(at.mono, 10, 64)
	a, e4 := time.Parse(time.RFC3339Nano, previous.wall)
	b, e5 := time.Parse(time.RFC3339Nano, end.wall)
	t, e6 := time.Parse(time.RFC3339Nano, at.wall)
	return e1 == nil && e2 == nil && e3 == nil && e4 == nil && e5 == nil && e6 == nil && lo <= v && v <= hi && !t.Before(a) && !t.After(b) && !b.Before(a)
}
