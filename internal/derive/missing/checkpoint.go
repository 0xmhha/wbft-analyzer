package missing

import (
	"sort"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
)

type checkpoint struct {
	height string
	source messages.Source
}

// HeaderNumbers retains checkpoint context outside the displayed cell range.
// Loading a fact does not itself validate a source or grant any coverage.
func HeaderNumbers(events []logs.Event, records []source.Record) []string {
	seen := map[string]bool{}
	for _, e := range events {
		if e.Record.Kind == event.NewHead && e.Record.View != nil && full(e.Record.View.Seq) {
			seen[e.Record.View.Seq] = true
		}
	}
	for _, r := range records {
		if r.Type == "step" && full(r.HeadNumber) {
			seen[r.HeadNumber] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// A journal checkpoint is a positive head observation, never event coverage.
// Exact stepped-outcome association binds its node/run to the event execution.
// Ambiguous recording inputs, loss, or conflicting source positions refuse it.
func journalCheckpoints(events []logs.Event, records []source.Record, hashes map[string]string) map[[2]string][]checkpoint {
	out := map[[2]string][]checkpoint{}
	if len(records) == 0 {
		return out
	}
	proof := messages.VerifyAssociation(records, events)
	if proof.Status != "matched" {
		return out
	}
	eligible := map[[2]string]bool{}
	for _, a := range proof.Anchors {
		if a.Status == "matched" {
			eligible[[2]string{canonical(a.Node), a.Run}] = true
		}
	}
	inputs := map[[2]string]map[string]bool{}
	eventInputs := map[[2]string]map[string]bool{}
	for _, e := range events {
		if e.Record.Src != "event" {
			continue
		}
		k := [2]string{canonical(e.Node), e.Run}
		if eventInputs[k] == nil {
			eventInputs[k] = map[string]bool{}
		}
		eventInputs[k][e.Input] = true
	}
	for _, r := range records {
		if r.Type != "segment" {
			continue
		}
		k := [2]string{canonical(r.Node), r.Run}
		if inputs[k] == nil {
			inputs[k] = map[string]bool{}
		}
		inputs[k][r.Input] = true
	}
	bad := map[[2]string]bool{}
	positions := map[[3]string]bool{}
	for _, r := range records {
		k := [2]string{canonical(r.Node), r.Run}
		if !inputs[k][r.Input] {
			continue
		}
		pos := [3]string{r.Input, r.File, strconv.FormatInt(r.Ordinal, 10)}
		if positions[pos] || r.Type == "gap" {
			bad[k] = true
		}
		positions[pos] = true
	}
	for _, r := range records {
		k := [2]string{canonical(r.Node), r.Run}
		if !eligible[k] || bad[k] || len(inputs[k]) != 1 || len(eventInputs[k]) != 1 || !inputs[k][r.Input] || r.Type != "step" || r.Step == "0" || !full(r.Step) || !full(r.Seq) || r.File == "" || r.Ordinal <= 0 || r.ClockSource != "recorded" || !full(r.HeadNumber) || hashes[r.HeadNumber] == "" || hashes[r.HeadNumber] != r.HeadHash {
			continue
		}
		if _, ok := recordedMono(r.Mono); !ok {
			continue
		}
		p := messages.Source{Kind: "message", Input: r.Input, File: r.File, Ordinal: r.Ordinal, Node: r.Node, Run: r.Run, Seq: r.Seq, Wall: r.Wall, Mono: r.Mono, ClockSource: r.ClockSource, Offset: r.Offset}
		out[k] = append(out[k], checkpoint{r.HeadNumber, p})
	}
	return out
}

func recordedMono(p *string) (uint64, bool) {
	if p == nil || !full(*p) {
		return 0, false
	}
	n, err := strconv.ParseUint(*p, 10, 63)
	return n, err == nil
}

// Checkpoints are lower bounds only, strictly before the target height. A
// startup head at the target cannot prove that height was captured in this run.
// The complete event run still needs its own later canonical NEW_HEAD and stop.
func checkpointBefore(points []checkpoint, height string, start, after, stop messages.Source) *checkpoint {
	a, aok := recordedMono(start.Mono)
	b, bok := recordedMono(after.Mono)
	c, cok := recordedMono(stop.Mono)
	if !aok || !bok || !cok || a >= b || b >= c {
		return nil
	}
	var best *checkpoint
	for i := range points {
		p := &points[i]
		m, ok := recordedMono(p.source.Mono)
		if !ok || m <= a || m >= b || cmpHeight(p.height, height) >= 0 {
			continue
		}
		if best == nil || cmpHeight(p.height, best.height) > 0 || p.height == best.height && p.source.Ordinal < best.source.Ordinal {
			best = p
		}
	}
	return best
}
