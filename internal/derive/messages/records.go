package messages

import (
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"sort"
)

const Version = "wbft-message-pairing/4"

type Issue struct {
	Source Source `json:"source"`
	Reason string `json:"reason"`
}
type Projection struct {
	Endpoints []Endpoint
	Issues    []Issue          `json:"issues"`
	Counts    map[string]int64 `json:"counts"`
}

func recordSource(r source.Record) Source {
	return Source{Kind: "message", Input: r.Input, File: r.File, Ordinal: r.Ordinal, Node: r.Node, Run: r.Run, Seq: r.Seq, Wall: r.Wall, Mono: r.Mono, ClockSource: r.ClockSource, Offset: r.Offset}
}

// ProjectRecords uses only explicit recording-node/peer direction. A recovered
// author is not the transmitting peer: relay traffic must not become a direct
// author-to-recipient link. Outcomes inherit no frame clock for measurement.
func ProjectRecords(records []source.Record) Projection {
	p := Projection{Endpoints: []Endpoint{}, Issues: []Issue{}, Counts: map[string]int64{}}
	for _, r := range records {
		p.Counts["records"]++
		if r.Type != "frame" {
			if r.Type == "gap" {
				p.Counts["gap_records"]++
			}
			continue
		}
		p.Counts["frames"]++
		reason := ""
		switch {
		case r.Dir != "in" && r.Dir != "out":
			reason = "unknown_direction"
		case r.Peer == "":
			reason = "unknown_peer"
		case r.Key == "":
			reason = "missing_key"
		case r.Decode == "key_mismatch":
			reason = "key_mismatch"
		case r.Phase == "":
			reason = "unknown_phase"
		}
		if reason != "" {
			p.Issues = append(p.Issues, Issue{recordSource(r), reason})
			p.Counts[reason]++
			continue
		}
		x := Endpoint{Source: recordSource(r), Strength: "link", Phase: r.Phase, Key: r.Key, Height: r.Height, Round: r.Round, Digest: r.Digest, Write: r.Write, Cause: r.Cause, Author: r.Signer}
		if r.Dir == "out" {
			x.Role = "send"
			x.Sender = r.Node
			x.Receiver = r.Peer
		} else {
			x.Role = "receive"
			x.Sender = r.Peer
			x.Receiver = r.Node
		}
		p.Endpoints = append(p.Endpoints, x)
		p.Counts["endpoints"]++
	}
	sort.Slice(p.Issues, func(i, j int) bool {
		a, b := p.Issues[i].Source, p.Issues[j].Source
		if a.Input != b.Input {
			return a.Input < b.Input
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Ordinal < b.Ordinal
	})
	return p
}
