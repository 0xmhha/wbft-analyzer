package messages

import (
	"encoding/hex"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"sort"
	"strings"
)

func value(e logs.Event, key string) string { v, _ := e.Record.Fields[key].(string); return v }
func eventPhase(e logs.Event) string {
	if p := value(e, "phase"); p != "" {
		return p
	}
	code := value(e, "code")
	if code == "" {
		code = value(e, "msg.code")
	}
	switch code {
	case "18":
		return "PRE-PREPARE"
	case "19":
		return "PREPARE"
	case "20":
		return "COMMIT"
	case "21":
		return "ROUND-CHANGE"
	}
	return ""
}

// Legacy extra-seal entries record processing after consensus. They are weak
// receipt evidence, not native outcomes or transport arrival timestamps.
func messageEvent(e logs.Event) bool {
	return e.Record.Kind == event.Send || e.Record.Kind == event.MsgOutcome ||
		(e.Record.Src == "log" && e.Record.Kind == event.ExtraSeal)
}

func eventSource(e logs.Event) Source {
	kind := "log"
	if e.Record.Src == "event" {
		kind = "event"
	}
	return Source{Kind: kind, Input: e.Input, Ordinal: e.Line, Node: e.Node, Run: e.Run, Seq: value(e, "seq"), Wall: e.Wall, Mono: e.Mono, ClockSource: "recorded"}
}

// ProjectEvents matches bytes when available and otherwise retains the weak
// logged tuple. A broadcast is expanded to recording nodes, not physical
// peers. Native SEND has no view; it is learned only from matching byte keys.
// Address/label aliases must be observed in the input, never guessed.
func ProjectEvents(events []logs.Event) Projection {
	p := Projection{Endpoints: []Endpoint{}, Issues: []Issue{}, Counts: map[string]int64{}}
	nodes := map[string]bool{}
	aliases := map[string]map[string]bool{}
	for _, e := range events {
		nodes[e.Node] = true
		if len(e.Node) == 42 && strings.HasPrefix(e.Node, "0x") {
			if _, err := hex.DecodeString(e.Node[2:]); err == nil {
				a := strings.ToLower(e.Node)
				if aliases[a] == nil {
					aliases[a] = map[string]bool{}
				}
				aliases[a][e.Node] = true
			}
		}
		// addr on other event kinds can identify a validator being added or
		// inspected, rather than this logger's node. Only the known consensus
		// logger context binds an address to its recording label.
		addr := ""
		if e.Record.Kind == event.Send || e.Record.Kind == event.MsgOutcome || e.Record.Kind == event.EngineStart {
			addr = value(e, "address")
		}
		if addr != "" {
			if aliases[addr] == nil {
				aliases[addr] = map[string]bool{}
			}
			aliases[addr][e.Node] = true
		}
	}
	nodeList := []string{}
	for n := range nodes {
		nodeList = append(nodeList, n)
	}
	sort.Strings(nodeList)
	resolve := func(a string) string {
		if nodes[a] {
			return a
		}
		if len(aliases[a]) == 1 {
			for n := range aliases[a] {
				return n
			}
		}
		return ""
	}
	for _, e := range events {
		p.Counts["records"]++
		if !messageEvent(e) {
			continue
		}
		x := Endpoint{Source: eventSource(e), Phase: eventPhase(e), Key: value(e, "dedup_key"), Digest: value(e, "digest"), Cause: value(e, "cause")}
		reason := ""
		if e.Record.View != nil && !e.ViewInferred {
			x.Height = e.Record.View.Seq
			x.Round = e.Record.View.Round
		}
		if x.Phase == "" {
			reason = "unknown_phase"
		}
		if x.Key != "" {
			x.Strength = "node"
		} else {
			x.Strength = "key"
			x.Height = value(e, "msg.sequence")
			x.Round = value(e, "msg.round")
			if x.Digest == "" {
				x.Digest = value(e, "block.hash")
			}
			if low64(x.Height) == "" || low64(x.Round) == "" {
				reason = "missing_identity"
			}
		}
		if e.Record.Kind == event.Send {
			x.Role = "send"
			x.Sender = e.Node
			// Legacy broadcasts log a zero source before signing. This denotes the
			// local broadcast, not an all-zero origin or an inferred received peer.
			if x.Cause == "relay" && x.Strength == "key" {
				reason = "unknown_origin"
			}
		} else {
			x.Role = "receive"
			x.Receiver = e.Node
			origin := value(e, "source")
			if origin == "" {
				origin = value(e, "msg.source")
			}
			x.Sender = resolve(origin)
			if x.Strength == "node" {
				if peer := resolve(value(e, "peer")); peer != "" {
					x.Sender = peer
				}
			}
			if x.Sender == "" {
				reason = "unknown_origin"
			}
			if x.Strength == "key" && x.Phase == "PRE-PREPARE" {
				reason = "unobserved_preprepare_receive"
			}
		}
		if reason != "" {
			p.Issues = append(p.Issues, Issue{x.Source, reason})
			p.Counts[reason]++
			continue
		}
		if x.Role == "send" {
			for _, n := range nodeList {
				y := x
				y.Receiver = n
				p.Endpoints = append(p.Endpoints, y)
				p.Counts["endpoints"]++
			}
		} else {
			p.Endpoints = append(p.Endpoints, x)
			p.Counts["endpoints"]++
		}
	}
	return p
}
