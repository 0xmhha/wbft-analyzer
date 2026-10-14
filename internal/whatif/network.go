package whatif

import (
	"sort"
	"strconv"
	"strings"
	"time"

	derived "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

// ArrivalInterval is an observed original receive, under the declared clock
// model. It is never a predicted arrival for generated or changed bytes.
type ArrivalInterval struct {
	From  string `json:"from_t_wall"`
	To    string `json:"to_t_wall"`
	Clock string `json:"clock_model"`
}

// NetworkBinding joins one verified original producer to recorded frame
// evidence. Multiple matching producers or repeated frames remain ambiguous.
type NetworkBinding struct {
	Original           Question         `json:"original_output"`
	Kind               string           `json:"kind"`
	PayloadSHA256      string           `json:"payload_sha256,omitempty"`
	Sender             string           `json:"sender"`
	Recipient          string           `json:"recipient"`
	Status             string           `json:"status"`
	ProducerCandidates int              `json:"producer_candidates"`
	SendCandidates     int              `json:"send_candidates"`
	ReceiveCandidates  int              `json:"receive_candidates"`
	Sends              []derived.Source `json:"sends"`
	Receives           []derived.Source `json:"receives"`
	Arrival            *ArrivalInterval `json:"original_arrival"`
}

type networkKey struct{ writer, payload, phase, peer, cause string }

func networkPhase(code string) string {
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
func networkCause(kind, cause string) bool {
	return kind == "broadcast" && (cause == "broadcast" || cause == "retry") || kind == "relay" && cause == "relay"
}
func sameFrame(a derived.Source, b source.Record) bool {
	return a.Input == b.Input && a.File == b.File && a.Ordinal == b.Ordinal && a.Node == b.Node && a.Run == b.Run && a.Seq == b.Seq
}

// BindNetwork operates on the entire selected input set, before any display
// window. Original actions must come from InspectEvidence's full baseline.
func (e *Evidence) BindNetwork(input, node string, records []source.Record, clock source.Clock) ([]NetworkBinding, error) {
	if e == nil || !addressPattern.MatchString(node) || len(records) > 1000000 {
		return nil, ErrEvidence
	}
	roots := []Question{}
	producers := map[networkKey][]Question{}
	for q, a := range e.actions {
		if a.Kind != "broadcast" && a.Kind != "relay" && a.Kind != "commit" {
			continue
		}
		roots = append(roots, q)
		if a.PayloadSHA256 == "" || a.RecipientEvidence != "validator_set" {
			continue
		}
		for _, peer := range a.Recipients {
			key := networkKey{q.Source.Writer, a.PayloadSHA256, networkPhase(a.Code), peer, a.Kind}
			producers[key] = append(producers[key], q)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		a, _ := strconv.ParseUint(roots[i].Source.Ordinal, 10, 64)
		b, _ := strconv.ParseUint(roots[j].Source.Ordinal, 10, 64)
		if a != b {
			return a < b
		}
		a, _ = strconv.ParseUint(roots[i].Output, 10, 64)
		b, _ = strconv.ParseUint(roots[j].Output, 10, 64)
		return a < b
	})
	projection := derived.ProjectRecords(records)
	c := derived.Clock{Model: clock.Model}
	if clock.SkewMS != nil {
		c.SkewMS = *clock.SkewMS
	} else if c.Model == "ntp" {
		c.Model = "unknown"
	}
	pairs := derived.PairEndpoints(projection.Endpoints, c)
	// The existing link matcher uses complete byte keys. Bind its pointers
	// back to the independently decoded SHA256 records; never convert a hash
	// algorithm or manufacture bytes from a dedup key.
	bySend := map[framePointer][]derived.Pair{}
	for _, pair := range pairs {
		if pair.Strength != "link" || pair.Path != "direct" && pair.Path != "relay" {
			continue
		}
		if pair.Send != nil {
			key := pointer(*pair.Send)
			bySend[key] = append(bySend[key], pair)
		} else {
			seen := map[framePointer]bool{}
			for _, candidate := range pair.Candidates {
				if candidate.Node == pair.Sender {
					key := pointer(candidate)
					if !seen[key] {
						bySend[key] = append(bySend[key], pair)
						seen[key] = true
					}
				}
			}
		}
	}
	recordIndex := map[framePointer]source.Record{}
	for _, r := range records {
		key := framePointer{r.Input, r.File, r.Ordinal}
		if _, exists := recordIndex[key]; exists {
			return nil, ErrEvidence
		}
		recordIndex[key] = r
	}
	frames := map[networkKey][]source.Record{}
	for _, r := range records {
		if r.Input != input || r.Node != node || r.Type != "frame" || r.Dir != "out" || r.Decode != "decoded" || !actionHashPattern.MatchString(r.PayloadSHA256) {
			continue
		}
		kind := "broadcast"
		if r.Cause == "relay" {
			kind = "relay"
		}
		if !networkCause(kind, r.Cause) {
			continue
		}
		key := networkKey{r.Run, r.PayloadSHA256, r.Phase, r.Peer, kind}
		frames[key] = append(frames[key], r)
	}
	out := []NetworkBinding{}
	for _, root := range roots {
		a := e.actions[root]
		peers := a.Recipients
		if len(peers) == 0 {
			peers = []string{""}
		}
		for _, peer := range peers {
			if len(out) >= 1000000 {
				return nil, ErrEvidence
			}
			b := NetworkBinding{Original: root, Kind: a.Kind, PayloadSHA256: a.PayloadSHA256, Sender: node, Recipient: peer, Status: "missing_send", Sends: []derived.Source{}, Receives: []derived.Source{}}
			switch {
			case a.Kind == "commit":
				b.Status = "application_delivery_unproved"
			case a.RecipientEvidence != "validator_set":
				b.Status = "unknown_membership"
			case peer == "":
				b.Status = "no_eligible_recipient"
			case a.PayloadEvidence == "recorded_signing_failure":
				b.Status = "recorded_signing_failure"
			case a.PayloadSHA256 == "":
				b.Status = "unsigned_request"
			default:
				key := networkKey{root.Source.Writer, a.PayloadSHA256, networkPhase(a.Code), peer, a.Kind}
				b.ProducerCandidates = len(producers[key])
				for _, r := range frames[key] {
					b.Sends = append(b.Sends, frameSource(r))
				}
				b.SendCandidates = len(b.Sends)
				if b.ProducerCandidates != 1 {
					b.Status = "ambiguous_producer"
				} else if b.SendCandidates > 1 {
					b.Status = "ambiguous_send"
				} else if b.SendCandidates == 1 {
					r := frames[key][0]
					if r.Write != "ok" {
						b.Status = "write_unproved"
					} else {
						ps := bySend[pointer(b.Sends[0])]
						if len(ps) != 1 {
							b.Status = "missing_receive"
						} else {
							joinPair(&b, ps[0], recordIndex, clock)
						}
					}
				}
			}
			out = append(out, b)
		}
	}
	return out, nil
}

type framePointer struct {
	input, file string
	ordinal     int64
}

func pointer(s derived.Source) framePointer { return framePointer{s.Input, s.File, s.Ordinal} }
func frameSource(r source.Record) derived.Source {
	return derived.Source{Kind: "message", Input: r.Input, File: r.File, Ordinal: r.Ordinal, Node: r.Node, Run: r.Run, Seq: r.Seq, Wall: r.Wall, Mono: r.Mono, ClockSource: r.ClockSource, Offset: r.Offset}
}

func joinPair(b *NetworkBinding, p derived.Pair, records map[framePointer]source.Record, clock source.Clock) {
	b.ReceiveCandidates = p.ReceiveCandidates
	for _, candidate := range p.Candidates {
		if candidate.Node == b.Recipient {
			b.Receives = append(b.Receives, candidate)
		}
	}
	if p.Receive != nil && len(b.Receives) == 0 {
		b.Receives = append(b.Receives, *p.Receive)
	}
	if p.ReceiveCandidates == 0 {
		b.Status = "missing_receive"
		return
	}
	if p.SendCandidates != 1 || p.ReceiveCandidates != 1 {
		b.Status = "ambiguous_delivery"
		return
	}
	if p.Send == nil || p.Receive == nil {
		b.Status = "missing_receive"
		return
	}
	receive, exists := records[pointer(*p.Receive)]
	if !exists || !sameFrame(*p.Receive, receive) || receive.Decode != "decoded" || receive.PayloadSHA256 != b.PayloadSHA256 {
		b.Status = "receive_bytes_unproved"
		return
	}
	if p.Status != "valid" {
		b.Status = p.Status
		return
	}
	t, err := time.Parse(time.RFC3339Nano, receive.Wall)
	if err != nil {
		b.Status = "missing_clock"
		return
	}
	bound := time.Duration(0)
	if clock.Model == "ntp" {
		if clock.SkewMS == nil || *clock.SkewMS < 0 || *clock.SkewMS > 86400000 {
			b.Status = "unknown_clock"
			return
		}
		bound = time.Duration(*clock.SkewMS) * time.Millisecond
	}
	if clock.Model != "shared-host" && clock.Model != "ntp" {
		b.Status = "unknown_clock"
		return
	}
	lo, hi := t.Add(-bound), t.Add(bound)
	if lo.Year() < 1 || hi.Year() > 9999 {
		b.Status = "invalid_clock"
		return
	}
	b.Arrival = &ArrivalInterval{lo.UTC().Format(time.RFC3339Nano), hi.UTC().Format(time.RFC3339Nano), clock.Model}
	b.Status = "observed_delivery"
}

// NetworkIntentIdentity includes bytes, code and ordered membership intent.
// Matching it alone never asserts unchanged output timing or delivery.
func NetworkIntentIdentity(a Action) string {
	return strings.Join(append([]string{a.Kind, a.Code, a.SHA256, a.PayloadEvidence, a.PayloadSHA256, a.RecipientEvidence}, a.Recipients...), "/")
}
