// Package missing classifies recorded participation evidence. Absence requires
// closed native-view coverage; a header-only observer is never a sender witness.
package missing

import (
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/observe/event"
)

const Version = "wbft-missing/3"

type Seal struct {
	Validator string `json:"validator"`
	Phase     string `json:"phase"`
	Index     string `json:"index"`
	Hash      string `json:"hash"`
	Round     string `json:"round"`
	Node      string `json:"node,omitempty"`
	DatasetID int64  `json:"dataset_id,omitempty"`
	Basis     string `json:"basis"` // own or previous; validated by the header adapter.
}
type Height struct {
	Hash            string
	ChildHash       string
	ChildParentHash string
	Index           string
	Number          string
	Round           string // Network decision round; empty when not established.
	Validators      []string
	Seals           []Seal
}
type Input struct {
	ID       string
	Complete bool
	Stats    logs.Stats
}
type Evidence struct {
	Role    string          `json:"role"`
	Source  messages.Source `json:"source"`
	Outcome string          `json:"outcome,omitempty"`
	Key     string          `json:"dedup_key,omitempty"`
}
type Cell struct {
	Index            string     `json:"index"`
	Height           string     `json:"height"`
	Round            string     `json:"round"`
	Validator        string     `json:"validator"`
	Phase            string     `json:"phase"`
	Class            string     `json:"class"`
	Reason           string     `json:"reason"`
	Strength         string     `json:"strength"`
	Quorum           int        `json:"quorum"`
	ReceiverCoverage int        `json:"receiver_coverage"`
	Sends            int        `json:"sends"`
	Accepted         int        `json:"accepted"`
	Rejected         int        `json:"rejected"`
	UnlinkedReceipts int        `json:"unlinked_receipts"`
	EvidenceCount    int        `json:"evidence_count"`
	Evidence         []Evidence `json:"evidence"`
	Seals            []Seal     `json:"seals"`
}
type view struct{ height, round string }
type vote struct {
	view
	author, phase string
}
type observed struct {
	key, role, outcome, strength string
	source                       messages.Source
}
type coverage struct {
	active            bool
	floorSource       messages.Source
	begin, end        messages.Source
	floor, floorState string
}

func canonical(s string) string           { return strings.ToLower(s) }
func value(e logs.Event, k string) string { s, _ := e.Record.Fields[k].(string); return s }
func point(e logs.Event) messages.Source {
	kind := "log"
	if e.Record.Src == "event" {
		kind = "event"
	}
	return messages.Source{Kind: kind, Input: e.Input, Ordinal: e.Line, Node: e.Node, Run: e.Run, Seq: value(e, "seq"), Wall: e.Wall, Mono: e.Mono, ClockSource: "recorded"}
}
func phase(e logs.Event) string {
	if s := value(e, "phase"); s != "" {
		return s
	}
	s := value(e, "code")
	if s == "" {
		s = value(e, "msg.code")
	}
	switch s {
	case "19":
		return "PREPARE"
	case "20":
		return "COMMIT"
	}
	return ""
}
func full(s string) bool {
	if len(s) == 0 || len(s) > 156 {
		return false
	}
	n, ok := new(big.Int).SetString(s, 10)
	return ok && n.Sign() >= 0 && n.String() == s && len(s) <= 156
}
func low(s string) string {
	if !full(s) {
		return ""
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 {
		return ""
	}
	return strconv.FormatUint(n.Uint64(), 10)
}

// Build receives one execution's complete event projection and validated header
// facts. Decoded frames supply byte identity, never receiver coverage or
// processing outcomes. Associated journal steps may supply a canonical lower
// checkpoint for a complete native event capture. Callers must validate any
// companion's execution scope.
// Header/source adapters must bind validator identities before calling Build.
func Build(heights []Height, events []logs.Event, records []source.Record, inputs []Input) ([]Cell, error) {
	return build(heights, heights, events, records, inputs)
}

// BuildRange bounds output before allocation while retaining all canonical heads
// and source records for identity and absence proofs outside the displayed range.
func BuildRange(heights []Height, events []logs.Event, records []source.Record, inputs []Input, from, to uint64) ([]Cell, error) {
	if to < from || to-from >= 1024 {
		return nil, fmt.Errorf("invalid classification range")
	}
	target := []Height{}
	for _, h := range heights {
		i, e := strconv.ParseUint(h.Index, 10, 64)
		if e != nil {
			return nil, e
		}
		if i >= from && i <= to {
			target = append(target, h)
		}
	}
	return build(heights, target, events, records, inputs)
}

func build(heights, target []Height, events []logs.Event, records []source.Record, inputs []Input) ([]Cell, error) {
	count := 0
	for _, h := range target {
		if len(h.Validators) > 50000 || count > 100000-2*len(h.Validators) {
			return nil, fmt.Errorf("classification exceeds 100000 cells")
		}
		count += 2 * len(h.Validators)
	}
	clean := map[string]bool{}
	for _, in := range inputs {
		clean[in.ID] = in.Complete && in.Stats.Malformed == 0 && in.Stats.SequenceGaps == 0 && in.Stats.Unknown == 0
	}
	ordered := append([]logs.Event(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Input != ordered[j].Input {
			return ordered[i].Input < ordered[j].Input
		}
		return ordered[i].Line < ordered[j].Line
	})
	members := map[string]bool{}
	views := map[view]bool{}
	for _, h := range heights {
		if !full(h.Number) || !full(h.Index) || len(h.Validators) == 0 || h.Round != "" && !full(h.Round) {
			return nil, fmt.Errorf("invalid height evidence")
		}
		seen := map[string]bool{}
		for _, v := range h.Validators {
			v = canonical(v)
			if v == "" || seen[v] {
				return nil, fmt.Errorf("duplicate or empty validator")
			}
			seen[v] = true
			members[v] = true
		}
		if h.Round != "" {
			views[view{h.Number, h.Round}] = true
		}
	}
	// Retain full views outside the displayed range before resolving a weak tuple.
	for _, e := range ordered {
		if e.Record.View != nil && !e.ViewInferred {
			views[view{e.Record.View.Seq, e.Record.View.Round}] = true
		}
	}
	type identity struct {
		view
		phase, author string
	}
	known := map[string]map[identity]bool{}
	add := func(key string, x identity) {
		if key == "" || x.author == "" || !full(x.height) || !full(x.round) {
			return
		}
		if known[key] == nil {
			known[key] = map[identity]bool{}
		}
		known[key][x] = true
		views[x.view] = true
	}
	for _, r := range records {
		if r.Type == "frame" && r.Decode == "decoded" {
			add(r.Key, identity{view{r.Height, r.Round}, r.Phase, canonical(r.Signer)})
		}
	}
	for _, e := range ordered {
		if e.Record.Src == "event" && e.Record.Kind == event.MsgOutcome && e.Record.View != nil && !e.ViewInferred {
			add(value(e, "dedup_key"), identity{view{e.Record.View.Seq, e.Record.View.Round}, phase(e), canonical(value(e, "source"))})
		}
	}
	tuples := map[view][]view{}
	for v := range views {
		if full(v.height) && full(v.round) {
			k := view{low(v.height), low(v.round)}
			tuples[k] = append(tuples[k], v)
		}
	}
	unpositioned := map[[2]string]bool{}
	obs := map[vote][]observed{}
	uncertain := map[vote]bool{}
	for _, e := range ordered {
		if e.Record.Kind != event.Send && e.Record.Kind != event.MsgOutcome {
			continue
		}
		ph := phase(e)
		if ph != "PREPARE" && ph != "COMMIT" {
			continue
		}
		key := value(e, "dedup_key")
		x := identity{phase: ph}
		strength := "node"
		if e.Record.View != nil && !e.ViewInferred {
			x.view = view{e.Record.View.Seq, e.Record.View.Round}
		}
		if e.Record.Kind == event.Send {
			if value(e, "cause") == "relay" {
				continue
			}
			x.author = canonical(e.Node)
		} else {
			x.author = canonical(value(e, "source"))
			if x.author == "" {
				x.author = canonical(value(e, "msg.source"))
			}
		}
		if key != "" && len(known[key]) == 1 {
			for k := range known[key] {
				if k.phase == ph && (x.view == view{} || x.view == k.view) && (x.author == "" || x.author == k.author) {
					x = k
				}
			}
		}
		if key == "" {
			strength = "key"
			weak := view{low(value(e, "msg.sequence")), low(value(e, "msg.round"))}
			if len(tuples[weak]) != 1 {
				for _, v := range tuples[weak] {
					uncertain[vote{v, x.author, ph}] = true
				}
				continue
			}
			x.view = tuples[weak][0]
		}
		if e.Record.Src == "event" && e.Record.Kind == event.Send && (!full(x.height) || !full(x.round)) {
			unpositioned[[2]string{canonical(e.Node), ph}] = true
		}
		if !views[x.view] || !members[x.author] {
			continue
		}
		k := vote{x.view, x.author, ph}
		if key != "" && len(known[key]) > 1 {
			uncertain[k] = true
			continue
		}
		role := "receive"
		if e.Record.Kind == event.Send {
			role = "send"
		}
		obs[k] = append(obs[k], observed{key, role, value(e, "outcome"), strength, point(e)})
	}
	covered := closedViews(ordered, clean, func(e logs.Event) bool {
		key := value(e, "dedup_key")
		if key == "" || len(known[key]) > 1 {
			return false
		}
		if e.Record.View != nil && !e.ViewInferred && value(e, "source") != "" {
			return true
		}
		// Prefilter duplicate outcomes omit view and source. Their exact byte key
		// can retain the uniquely recorded identity, without borrowing current view.
		if len(known[key]) == 1 {
			for x := range known[key] {
				return x.phase == phase(e) && x.author != "" && full(x.height) && full(x.round)
			}
		}
		return false
	})
	captures := senderCaptures(ordered, records, clean, heights, target)
	cells := make([]Cell, 0, count)
	for _, h := range target {
		for _, who := range h.Validators {
			who = canonical(who)
			for _, ph := range []string{"PREPARE", "COMMIT"} {
				v := view{h.Number, h.Round}
				k := vote{v, who, ph}
				c := Cell{Index: h.Index, Height: h.Number, Round: h.Round, Validator: who, Phase: ph, Class: "UNKNOWN", Reason: "insufficient_evidence", Strength: "unavailable", Quorum: validator.QuorumSize(len(h.Validators)), Evidence: []Evidence{}, Seals: []Seal{}}
				addEvidence := func(e Evidence) {
					c.EvidenceCount++
					if len(c.Evidence) < 32 {
						c.Evidence = append(c.Evidence, e)
					}
				}
				for _, s := range h.Seals {
					if canonical(s.Validator) == who && s.Phase == ph && validSeal(h, s) {
						c.Seals = append(c.Seals, s)
					}
				}
				if len(c.Seals) > 0 {
					c.Class = "SEALED"
					c.Reason = "header_seal"
					c.Strength = "header"
					cells = append(cells, c)
					continue
				}
				if h.Round == "" {
					c.Reason = "decision_round_unknown"
					cells = append(cells, c)
					continue
				}
				receiverEvidence := []Evidence{}
				for _, receiver := range h.Validators {
					cs := covered[canonical(receiver)][v]
					if len(cs) > 0 {
						c.ReceiverCoverage++
						receiverEvidence = append(receiverEvidence, Evidence{Role: "receiver_coverage_begin", Source: cs[0].begin})
						receiverEvidence = append(receiverEvidence, Evidence{Role: "receiver_coverage_end", Source: cs[0].end})
					}
				}
				xs := obs[k]
				sendKeys := map[string]bool{}
				receivedKeys := map[string]bool{}
				weakSend := false
				unknownOutcome := false
				for _, x := range xs {
					if x.role == "send" {
						c.Sends++
						if x.key != "" {
							sendKeys[x.key] = true
						} else {
							weakSend = true
						}
						if x.strength == "key" {
							c.Strength = "key"
						} else if c.Strength != "key" {
							c.Strength = "node"
						}
					}
					if x.role == "receive" && x.key != "" {
						receivedKeys[x.key] = true
					}
				}
				if weakSend && len(receivedKeys) > 1 {
					uncertain[k] = true
				}
				for _, x := range xs {
					if x.role == "send" {
						addEvidence(Evidence{Role: "send", Source: x.source, Key: x.key})
						continue
					}
					if !weakSend && !sendKeys[x.key] {
						c.UnlinkedReceipts++
						addEvidence(Evidence{Role: "unlinked_outcome", Source: x.source, Key: x.key, Outcome: x.outcome})
						continue
					}
					switch x.outcome {
					case "ACCEPT":
						c.Accepted++
					case "IGNORE", "DROP_SILENT", "DISCONNECT":
						c.Rejected++
					default:
						unknownOutcome = true
					}
					addEvidence(Evidence{Role: "outcome", Source: x.source, Key: x.key, Outcome: x.outcome})
				}
				switch {
				case uncertain[k]:
					c.Reason = "ambiguous_identity"
				case c.Sends > 0 && c.Accepted > 0:
					c.Class = "SENT_ACCEPTED_NOT_SEALED"
					c.Reason = "recorded_accept"
				case c.Sends > 0 && c.Rejected > 0 && !unknownOutcome:
					c.Class = "SENT_REJECTED"
					c.Reason = "recorded_rejections_only"
				case c.UnlinkedReceipts > 0:
					c.Reason = "unlinked_receipt"
				case c.Sends > 0 && c.Accepted == 0 && c.Rejected == 0 && !unknownOutcome && c.ReceiverCoverage >= c.Quorum:
					c.Class = "SENT_UNSEEN"
					c.Reason = "quorum_closed_view_coverage"
				case c.Sends == 0 && !unpositioned[[2]string{who, ph}] && hasActiveCoverage(covered[who][v]):
					c.Class = "NOT_SENT"
					c.Reason = "closed_native_view"
					c.Strength = "node"
					for _, proof := range covered[who][v] {
						if !proof.active {
							continue
						}
						addEvidence(Evidence{Role: "sender_coverage_begin", Source: proof.begin})
						addEvidence(Evidence{Role: "sender_coverage_end", Source: proof.end})
						if proof.floorState == "set" || proof.floorState == "kept" {
							a, _ := new(big.Int).SetString(h.Number, 10)
							b, ok := new(big.Int).SetString(proof.floor, 10)
							if ok && a.Cmp(b) <= 0 {
								c.Reason = "sign_floor"
								addEvidence(Evidence{Role: "sign_floor", Source: proof.floorSource})
							}
						}
					}
				case c.Sends == 0 && !unpositioned[[2]string{who, ph}] && len(captures[who][h.Number]) > 0:
					c.Class = "NOT_SENT"
					c.Reason = "complete_active_event_capture"
					c.Strength = "node"
					for _, e := range captures[who][h.Number] {
						if e.Role == "sign_floor" {
							c.Reason = "sign_floor"
						}
						addEvidence(e)
					}
				case c.Sends == 0 && unpositioned[[2]string{who, ph}]:
					c.Reason = "unpositioned_sender_identity"
				case c.Sends > 0:
					c.Reason = "receiver_coverage_insufficient"
				}
				for _, e := range receiverEvidence {
					addEvidence(e)
				}
				cells = append(cells, c)
			}
		}
	}
	return cells, nil
}

// Coverage follows original source order, not wall clocks. Only a clean native
// input, a recorded round entry and its same-run closing boundary prove absence.
// Receiver loss signals invalidate the input rather than becoming zero counts.
func closedViews(events []logs.Event, clean map[string]bool, identified func(logs.Event) bool) map[string]map[view][]coverage {
	out := map[string]map[view][]coverage{}
	type key struct{ input, node, run string }
	type active struct {
		v     view
		proof coverage
	}
	current := map[key]active{}
	starts := map[key]coverage{}
	bad := map[string]bool{}
	for _, e := range events {
		if e.Record.Src == "event" && e.Record.Kind == event.Health && (value(e, "what") == "peer_inbound_overflow" || value(e, "what") == "peer_inbound_disconnect") {
			bad[e.Input] = true
		}
	}
	for _, e := range events {
		if e.Record.Src == "event" && e.Record.Kind == event.MsgOutcome && (phase(e) == "PREPARE" || phase(e) == "COMMIT") && !identified(e) {
			bad[e.Input] = true
		}
	}
	closeView := func(k key, end messages.Source) {
		a, ok := current[k]
		if !ok {
			return
		}
		a.proof.end = end
		if out[k.node] == nil {
			out[k.node] = map[view][]coverage{}
		}
		out[k.node][a.v] = append(out[k.node][a.v], a.proof)
		delete(current, k)
	}
	for _, e := range events {
		if e.Record.Src != "event" || !clean[e.Input] || bad[e.Input] {
			continue
		}
		k := key{e.Input, canonical(e.Node), e.Run}
		if e.Record.Kind == event.NodeStart && value(e, "seq") == "0" {
			starts[k] = coverage{active: activeValidator(e), floorSource: point(e), floor: value(e, "sign_floor_height"), floorState: value(e, "sign_floor_status")}
			continue
		}
		if _, ok := starts[k]; !ok {
			continue
		}
		if e.Record.Kind == event.RoundEnter && e.Record.View != nil && !e.ViewInferred {
			v := view{e.Record.View.Seq, e.Record.View.Round}
			if !full(v.height) || !full(v.round) {
				continue
			}
			if a, ok := current[k]; ok {
				if a.v == v {
					continue
				}
				closeView(k, point(e))
			}
			proof := starts[k]
			proof.begin = point(e)
			current[k] = active{v, proof}
		} else if e.Record.Kind == event.EngineStop || e.Record.Kind == event.NodeStop {
			closeView(k, point(e))
		}
	}
	for k, a := range current {
		delete(out[k.node], a.v)
	}
	return out
}

func validSeal(h Height, s Seal) bool {
	if s.Hash == "" || !full(s.Round) {
		return false
	}
	if s.Basis == "own" {
		return s.Index == h.Index && s.Hash == h.Hash && h.Hash != ""
	}
	i, ok := new(big.Int).SetString(h.Index, 10)
	return s.Basis == "previous" && ok && s.Index == i.Add(i, big.NewInt(1)).String() && h.ChildHash != "" && s.Hash == h.ChildHash && h.ChildParentHash == h.Hash && h.Hash != ""
}

// A complete, active-validator run may import a range without its core entering
// every view. It still records every local SEND. Two canonical imported heads
// bracket that range; an associated canonical journal checkpoint may replace
// its lower bound. A terminal NODE_STOP and clean source diagnostics prove
// the event capture's end. This is sender coverage only: imported headers never
// establish receiver coverage, and opaque SEND identities block absence.
func senderCaptures(events []logs.Event, records []source.Record, clean map[string]bool, heights, target []Height) map[string]map[string][]Evidence {
	out := map[string]map[string][]Evidence{}
	hashes := map[string]string{}
	for _, h := range heights {
		if h.Hash != "" {
			hashes[h.Number] = h.Hash
		}
	}
	checkpoints := journalCheckpoints(events, records, hashes)
	type key struct{ input, node, run string }
	type head struct {
		height string
		source messages.Source
	}
	type run struct {
		start, stop       messages.Source
		heads             []head
		active, bad       bool
		floor, floorState string
	}
	runs := map[key]*run{}
	for _, e := range events {
		if e.Record.Src != "event" || !clean[e.Input] {
			continue
		}
		k := key{e.Input, canonical(e.Node), e.Run}
		if e.Record.Kind == event.NodeStart && value(e, "seq") == "0" {
			active, _ := e.Record.Fields["validator"].(bool)
			runs[k] = &run{start: point(e), active: active, floor: value(e, "sign_floor_height"), floorState: value(e, "sign_floor_status")}
			continue
		}
		r := runs[k]
		if r == nil {
			continue
		}
		if e.Record.Kind == event.NodeStop {
			r.stop = point(e)
		}
		if e.Record.Kind == event.Health && (value(e, "what") == "peer_inbound_overflow" || value(e, "what") == "peer_inbound_disconnect") {
			r.bad = true
		}
		if e.Record.Kind == event.NewHead && e.Record.View != nil {
			n := e.Record.View.Seq
			if hash := hashes[n]; hash != "" && hash == value(e, "hash") {
				r.heads = append(r.heads, head{n, point(e)})
			}
		}
	}
	keys := make([]key, 0, len(runs))
	for k := range runs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.input != b.input {
			return a.input < b.input
		}
		if a.node != b.node {
			return a.node < b.node
		}
		return a.run < b.run
	})
	for _, k := range keys {
		r := runs[k]
		if !r.active || r.bad || r.stop.Ordinal <= r.start.Ordinal {
			continue
		}

		valid := r.heads[:0]
		for _, x := range r.heads {
			if x.source.Ordinal > r.start.Ordinal && x.source.Ordinal < r.stop.Ordinal {
				valid = append(valid, x)
			}
		}
		r.heads = valid
		sort.SliceStable(r.heads, func(i, j int) bool { return cmpHeight(r.heads[i].height, r.heads[j].height) < 0 })
		for _, h := range target {
			pos := sort.Search(len(r.heads), func(i int) bool { return cmpHeight(r.heads[i].height, h.Number) >= 0 })
			var lo, hi *head
			if pos < len(r.heads) {
				hi = &r.heads[pos]
				if hi.height == h.Number {
					lo = hi
				}
			}
			if lo == nil && pos > 0 {
				lo = &r.heads[pos-1]
			}

			if lo == nil && hi != nil {
				if p := checkpointBefore(checkpoints[[2]string{k.node, k.run}], h.Number, r.start, hi.source, r.stop); p != nil {
					lo = &head{p.height, p.source}
				}
			}
			if lo == nil || hi == nil || lo.source.Kind != "message" && lo.source.Ordinal > hi.source.Ordinal {
				continue
			}
			if out[k.node] == nil {
				out[k.node] = map[string][]Evidence{}
			}
			proof := []Evidence{{Role: "sender_capture_start", Source: r.start}, {Role: "sender_canonical_head_before", Source: lo.source}, {Role: "sender_canonical_head_after", Source: hi.source}, {Role: "sender_capture_stop", Source: r.stop}}
			if (r.floorState == "set" || r.floorState == "kept") && full(r.floor) && cmpHeight(h.Number, r.floor) <= 0 {
				proof = append(proof, Evidence{Role: "sign_floor", Source: r.start})
			}
			out[k.node][h.Number] = append(out[k.node][h.Number], proof...)
		}
	}
	return out
}
func cmpHeight(a, b string) int {
	x, _ := new(big.Int).SetString(a, 10)
	y, _ := new(big.Int).SetString(b, 10)
	return x.Cmp(y)
}

func activeValidator(e logs.Event) bool { v, _ := e.Record.Fields["validator"].(bool); return v }
func hasActiveCoverage(cs []coverage) bool {
	for _, c := range cs {
		if c.active {
			return true
		}
	}
	return false
}
