package reconstruct

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
)

type processingLog struct {
	event   logs.Event
	payload *logs.PayloadWitness
}
type processingHandler struct {
	witness    ProcessingWitness
	wall       time.Time
	valid      bool
	accepts    int
	acceptWall time.Time
}
type processingCollector struct {
	node                                                 string
	index                                                map[string]int
	handlers                                             []processingHandler
	payloads                                             []processingLog
	frames                                               []messages.Record
	pending                                              int
	proposerRun, proposerHeight, proposerRound, proposer string
	logRuns, frameRuns                                   map[string]bool
	unlocated                                            int64
	invalidPayloads                                      int64
	count                                                int
}

func newProcessing(m Manifest, index map[string]int) *processingCollector {
	p := &processingCollector{node: m.Node, index: index, pending: -1, logRuns: map[string]bool{}, frameRuns: map[string]bool{}}
	for _, s := range m.Scopes {
		p.logRuns[s.LogRun] = false
		p.frameRuns[s.FrameRun] = false
	}
	return p
}
func field(e logs.Event, key string) string { s, _ := e.Record.Fields[key].(string); return s }
func logPoint(e logs.Event) Point {
	return Point{Kind: "log", File: "log", Line: e.Line, Run: e.Run, ViewInferred: e.ViewInferred}
}
func framePoint(r messages.Record) Point {
	return Point{Kind: "frame", File: r.File, Line: r.Ordinal, Run: r.Run, Sequence: r.Seq}
}
func (p *processingCollector) reserve() error {
	p.count++
	if p.count > MaxProcessingRecords {
		return errors.New("reconstruction processing sources exceed 100000 records")
	}
	return nil
}
func (p *processingCollector) log(e logs.Event, raw []byte) error {
	if _, ok := p.logRuns[e.Run]; ok {
		p.logRuns[e.Run] = true
	}
	boundary := e.Record.Kind == event.EngineStart || e.Record.Kind == event.EngineStop || e.Record.Kind == event.NewHead || e.Record.Kind == event.RoundEnter || e.Record.Kind == event.BuildRequest || e.Record.Kind == event.TimerFire
	if boundary {
		p.pending = -1
	}
	if e.Record.Kind == event.EngineStart || e.Record.Kind == event.EngineStop || e.Record.Kind == event.NewHead {
		p.proposer = ""
	}
	if e.Record.Kind == event.RoundEnter && e.Record.View != nil {
		p.proposerRun, p.proposerHeight, p.proposerRound, p.proposer = e.Run, e.Record.View.Seq, e.Record.View.Round, field(e, "next.proposer")
	}
	phase := field(e, "phase")
	handle := field(e, "action") == "handle"
	accepted := e.Record.Kind == event.PreprepareAccept
	var payload *logs.PayloadWitness
	if e.Level == "trace" || e.Record.Kind == event.Send && phase == "ROUND-CHANGE" {
		payload = logs.MessagePayload(raw)
	}
	if handle || accepted || payload != nil {
		if address := field(e, "address"); address != "" && address != p.node {
			return errors.New("reconstruction processing node identity mismatch")
		}
	}
	if payload != nil {
		height := payload.Height
		if height == "" && e.Record.View != nil {
			height = e.Record.View.Seq
		}
		if _, ok := p.index[height]; ok {
			if err := p.reserve(); err != nil {
				return err
			}
			if payload.Status != "decoded" {
				p.invalidPayloads++
			}
			p.payloads = append(p.payloads, processingLog{e, payload})
		}
	}
	if handle {
		p.pending = -1
		height, round := field(e, "msg.sequence"), field(e, "msg.round")
		inferred := false
		if phase == "PRE-PREPARE" && height == "" && round == "" && e.Record.View != nil {
			height, round = e.Record.View.Seq, e.Record.View.Round
			inferred = true
		}
		if height == "" {
			p.unlocated++
		}
		if _, ok := p.index[height]; !ok {
			return nil
		}
		if err := p.reserve(); err != nil {
			return err
		}
		source := field(e, "msg.source")
		if phase == "PRE-PREPARE" && source == "" && p.proposerRun == e.Run && p.proposerHeight == height && p.proposerRound == round {
			source = p.proposer
		}
		point := logPoint(e)
		point.ViewInferred = inferred
		code := map[string]string{"PRE-PREPARE": "18", "PREPARE": "19", "COMMIT": "20", "ROUND-CHANGE": "21"}[phase]
		valid := code != "" && round != "" && addressPattern.MatchString(source) && field(e, "address") == p.node
		if actual := field(e, "msg.code"); actual != "" {
			valid = valid && actual == code
		} else {
			valid = valid && phase == "PRE-PREPARE"
		}
		h := processingHandler{witness: ProcessingWitness{DeclaredDigest: field(e, "digest"), Phase: phase, Height: height, Round: round, Signer: source, Handler: point, Status: "missing", Candidates: []ProcessingCandidate{}, ApplicationVerification: "not_applicable"}, valid: valid}
		h.wall, _ = time.Parse(time.RFC3339Nano, e.Wall)
		if phase == "PRE-PREPARE" && h.witness.DeclaredDigest == "" {
			h.witness.DeclaredDigest = field(e, "proposal.hash")
		}
		if phase == "PRE-PREPARE" {
			h.witness.ApplicationVerification = "unavailable"
		}
		p.handlers = append(p.handlers, h)
		if phase == "PRE-PREPARE" {
			p.pending = len(p.handlers) - 1
		}
		return nil
	}
	if p.pending >= 0 {
		h := &p.handlers[p.pending]
		same := h.witness.Handler.Run == e.Run && e.Record.View != nil && h.witness.Height == e.Record.View.Seq && h.witness.Round == e.Record.View.Round
		if accepted && same && field(e, "address") == p.node {
			h.accepts++
			h.acceptWall, _ = time.Parse(time.RFC3339Nano, e.Wall)
			point := logPoint(e)
			h.witness.Accepted = &point
		} else if accepted || e.Record.Kind == event.ProposalDeferred || phase == "PRE-PREPARE" && (e.Level == "warn" || e.Level == "error") {
			p.pending = -1
		}
	}
	return nil
}
func (p *processingCollector) frame(r messages.Record) error {
	if _, ok := p.frameRuns[r.Run]; ok {
		p.frameRuns[r.Run] = true
	}
	if _, ok := p.index[r.Height]; !ok || r.Type != "frame" || r.Decode != "decoded" {
		return nil
	}
	if err := p.reserve(); err != nil {
		return err
	}
	p.frames = append(p.frames, r)
	return nil
}

type candidateKey struct{ phase, height, round, signer, run, digest string }
type timedCandidate struct {
	wall  time.Time
	value ProcessingCandidate
}
type candidateIndex map[candidateKey][]timedCandidate

func (x candidateIndex) add(key candidateKey, wall string, value ProcessingCandidate) {
	at, err := time.Parse(time.RFC3339Nano, wall)
	if err == nil {
		x[key] = append(x[key], timedCandidate{at, value})
	}
}
func (x candidateIndex) sort() {
	for key := range x {
		sort.SliceStable(x[key], func(i, j int) bool { return x[key][i].wall.Before(x[key][j].wall) })
	}
}
func choose(xs []timedCandidate, from, to time.Time) (int64, []ProcessingCandidate) {
	a := sort.Search(len(xs), func(i int) bool { return !xs[i].wall.Before(from) })
	b := sort.Search(len(xs), func(i int) bool { return !xs[i].wall.Before(to) })
	if b < a {
		return 0, []ProcessingCandidate{}
	}
	n := b - a
	if n > 4 {
		n = 4
	}
	out := make([]ProcessingCandidate, 0, n)
	for _, c := range xs[a : a+n] {
		out = append(out, c.value)
	}
	return int64(b - a), out
}
func (p *processingCollector) finish(ctx context.Context, m Manifest, out *Assessment) error {
	scopes, err := p.scopes(ctx, m)
	if err != nil {
		return err
	}
	out.Sources.ProcessingVersion = ProcessingVersion
	out.Sources.ProcessingUnlocated = p.unlocated
	out.Sources.ProcessingInvalidPayloads = p.invalidPayloads
	out.Sources.ProcessingScopes = scopes
	byRun := map[string]int{}
	for i, s := range m.Scopes {
		byRun[s.LogRun] = i
	}
	candidates := candidateIndex{}
	for _, r := range p.frames {
		if r.Dir != "in" || r.Peer == "" || r.Signature != "recovered" {
			continue
		}
		value := ProcessingCandidate{Source: framePoint(r), Peer: r.Peer, PayloadSHA256: r.PayloadSHA256, Digest: r.Digest}
		for _, run := range []string{"frame:", "frame:" + r.Run} {
			candidates.add(candidateKey{r.Phase, r.Height, r.Round, r.Signer, run, ""}, r.Wall, value)
			if r.Digest != "" {
				candidates.add(candidateKey{r.Phase, r.Height, r.Round, r.Signer, run, r.Digest}, r.Wall, value)
			}
		}
	}
	for _, r := range p.payloads {
		x := r.payload
		if x.Status != "decoded" || x.Signer != p.node || field(r.event, "address") != p.node {
			continue
		}
		value := ProcessingCandidate{Source: logPoint(r.event), Peer: p.node, PayloadSHA256: x.SHA256, Digest: x.Digest}
		candidates.add(candidateKey{x.Phase, x.Height, x.Round, x.Signer, "local:" + r.event.Run, ""}, r.event.Wall, value)
		candidates.add(candidateKey{x.Phase, x.Height, x.Round, x.Signer, "local:" + r.event.Run, x.Digest}, r.event.Wall, value)
	}
	candidates.sort()
	incomplete := p.invalidPayloads != 0 || out.Sources.LogStats.ClockRegressions != 0 || out.Sources.LogStats.Malformed != 0 || out.Sources.LogStats.Unknown != 0
	if s := out.Sources.FrameStats; s != nil {
		incomplete = incomplete || s.GapRecords != 0 || s.SequenceGaps != 0 || s.PartialRuns != 0 || s.ClockRegressions != 0 || s.Undecoded != 0 || s.UnknownPeers != 0
	}
	for i := range p.handlers {
		if err := ctx.Err(); err != nil {
			return err
		}
		h := &p.handlers[i]
		v := &h.witness
		lower, upper := time.Time{}, h.wall
		run := "frame:"
		anchored := false
		inScope := false
		if n, ok := byRun[v.Handler.Run]; ok {
			d := m.Scopes[n]
			from, _ := time.Parse(time.RFC3339Nano, d.From)
			to, _ := time.Parse(time.RFC3339Nano, d.To)
			if to.Before(upper) {
				upper = to
			}
			lower = from
			inScope = !h.wall.Before(from) && !h.wall.After(to)
			anchored = scopes[n].Status == "declared_content_anchored" && inScope
			run = "frame:" + d.FrameRun
		}
		if v.Signer == p.node {
			run = "local:" + v.Handler.Run
		}
		v.CandidateCount, v.Candidates = choose(candidates[candidateKey{v.Phase, v.Height, v.Round, v.Signer, run, v.DeclaredDigest}], lower, upper)
		v.CandidatesTruncated = v.CandidateCount > int64(len(v.Candidates))
		switch {
		case !h.valid:
			v.Status = "invalid_context"
		case !inScope && byRunHas(byRun, v.Handler.Run):
			v.Status = "outside_scope"
		case v.CandidateCount == 0:
			v.Status = "missing"
		case v.CandidateCount > 1:
			v.Status = "ambiguous"
		case !anchored:
			v.Status = "unbound_scope"
		case incomplete:
			v.Status = "incomplete_capture"
		default:
			v.Status = "linked"
		}
		if v.Phase == "PRE-PREPARE" && h.accepts > 0 {
			v.ApplicationVerification = "unbound_acceptance"
			if h.accepts != 1 {
				v.ApplicationVerification = "ambiguous"
				v.Accepted = nil
			} else if v.Status == "linked" && !h.acceptWall.Before(h.wall) && acceptanceInScope(m.Scopes[byRun[v.Handler.Run]], h.acceptWall) {
				v.ApplicationVerification = "success_witness"
			}
		}
	}
	uses := map[Point]int64{}
	for _, h := range p.handlers {
		if h.witness.CandidateCount == 1 {
			uses[h.witness.Candidates[0].Source]++
		}
	}
	for _, h := range p.handlers {
		v := h.witness
		if v.CandidateCount == 1 {
			v.SourceUses = uses[v.Candidates[0].Source]
			if v.SourceUses > 1 && v.Status == "linked" {
				v.Status = "reused_source"
				if v.ApplicationVerification == "success_witness" {
					v.ApplicationVerification = "unbound_acceptance"
				}
			}
		}
		out.Heights[p.index[v.Height]].Processing = append(out.Heights[p.index[v.Height]].Processing, v)
	}
	return nil
}

// scopes corroborates explicit same-execution declarations with two distinct
// signed own-message contents. Repeated writes of one payload count once.
func (p *processingCollector) scopes(ctx context.Context, m Manifest) ([]ProcessingScope, error) {
	result := make([]ProcessingScope, 0, len(m.Scopes))
	type anchorKey struct{ run, sha string }
	frames := map[anchorKey][]messages.Record{}
	for _, r := range p.frames {
		if r.Dir == "out" && r.Signature == "recovered" && r.Signer == p.node {
			key := anchorKey{r.Run, r.PayloadSHA256}
			frames[key] = append(frames[key], r)
		}
	}
	for key := range frames {
		sort.SliceStable(frames[key], func(i, j int) bool {
			a, _ := time.Parse(time.RFC3339Nano, frames[key][i].Wall)
			b, _ := time.Parse(time.RFC3339Nano, frames[key][j].Wall)
			return a.Before(b)
		})
	}
	for _, d := range m.Scopes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		from, _ := time.Parse(time.RFC3339Nano, d.From)
		to, _ := time.Parse(time.RFC3339Nano, d.To)
		s := ProcessingScope{From: d.From, To: d.To, LogRun: d.LogRun, FrameRun: d.FrameRun, Status: "declared_unanchored", Anchors: []ContentAnchor{}}
		seen := map[string]bool{}
		for _, entry := range p.payloads {
			e, x := entry.event, entry.payload
			if e.Run != d.LogRun {
				continue
			}
			if x.Status != "decoded" || x.Signer != p.node || field(e, "address") != p.node || seen[x.SHA256] {
				continue
			}
			at, _ := time.Parse(time.RFC3339Nano, e.Wall)
			if at.Before(from) || at.After(to) {
				continue
			}
			matching := frames[anchorKey{d.FrameRun, x.SHA256}]
			first := sort.Search(len(matching), func(i int) bool { wall, _ := time.Parse(time.RFC3339Nano, matching[i].Wall); return !wall.Before(at) })
			if first < len(matching) {
				r := matching[first]
				wall, _ := time.Parse(time.RFC3339Nano, r.Wall)
				if !wall.After(to) && r.Phase == x.Phase && r.Height == x.Height && r.Round == x.Round {
					seen[x.SHA256] = true
					s.DistinctPayloads++
					if len(s.Anchors) < 16 {
						s.Anchors = append(s.Anchors, ContentAnchor{x.SHA256, logPoint(e), framePoint(r)})
					}
				}
			}
		}
		if !p.logRuns[d.LogRun] || !p.frameRuns[d.FrameRun] {
			return nil, errors.New("reconstruction processing scope names an unavailable run")
		}
		if s.DistinctPayloads >= 2 {
			s.Status = "declared_content_anchored"
		}
		result = append(result, s)
	}
	return result, nil
}

func validScopes(m Manifest) bool {
	if len(m.Scopes) > 100 || len(m.Scopes) > 0 && m.Frames == nil {
		return false
	}
	used := map[string]bool{}
	for i, s := range m.Scopes {
		from, e1 := time.Parse(time.RFC3339Nano, s.From)
		to, e2 := time.Parse(time.RFC3339Nano, s.To)
		if !runIDPattern.MatchString(s.LogRun) || !runIDPattern.MatchString(s.FrameRun) || used[s.LogRun] || e1 != nil || e2 != nil || !to.After(from) || to.Sub(from) > 24*time.Hour {
			return false
		}
		for _, prior := range m.Scopes[:i] {
			if prior.FrameRun == s.FrameRun {
				a, _ := time.Parse(time.RFC3339Nano, prior.From)
				b, _ := time.Parse(time.RFC3339Nano, prior.To)
				if !to.Before(a) && !from.After(b) {
					return false
				}
			}
		}
		used[s.LogRun] = true
	}
	return true
}

func byRunHas(m map[string]int, key string) bool { _, ok := m[key]; return ok }
func acceptanceInScope(s RunScope, at time.Time) bool {
	from, _ := time.Parse(time.RFC3339Nano, s.From)
	to, _ := time.Parse(time.RFC3339Nano, s.To)
	return !at.Before(from) && !at.After(to)
}
