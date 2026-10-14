package whatif

import (
	"encoding/json"
	"sort"
	"strconv"
	"time"
)

const NetworkVersion = "wbft-network-effects/1"

type NetworkInput struct {
	Input  string `json:"input"`
	Kind   string `json:"kind"`
	Node   string `json:"node"`
	SHA256 string `json:"sha256"`
	Status string `json:"status"`
}
type NetworkScope struct {
	Status string         `json:"status"`
	SHA256 string         `json:"sha256"`
	Clock  string         `json:"clock_model"`
	SkewMS *int64         `json:"skew_ms,omitempty"`
	Inputs []NetworkInput `json:"inputs"`
}
type OutputPosition struct {
	Execution string `json:"execution_step"`
	Output    string `json:"output"`
	Mono      string `json:"t_mono_ns"`
}
type NetworkEffect struct {
	ID               string          `json:"id"`
	Kind             string          `json:"kind"`
	Status           string          `json:"status"`
	ActionKind       string          `json:"action_kind"`
	PayloadSHA256    string          `json:"payload_sha256,omitempty"`
	Current          *OutputPosition `json:"current_output"`
	Original         *Question       `json:"original_output"`
	OriginCandidates int             `json:"origin_candidates"`
	Bindings         []string        `json:"binding_ids"`
}
type NetworkSummary struct {
	Unproved               int64            `json:"unproved_effects"`
	Version                string           `json:"version"`
	Status                 string           `json:"status"`
	Scope                  NetworkScope     `json:"scope"`
	Bindings               int64            `json:"bindings"`
	Effects                int64            `json:"effects"`
	Unchanged              int64            `json:"unchanged_under_model"`
	Changed                int64            `json:"changed_intents"`
	FirstUnproved          *OutputPosition  `json:"first_unproved_output"`
	ObservedRemovedArrival *ArrivalInterval `json:"first_observed_removed_arrival"`
}

// NetworkPlanner compares intents under the declared execution model. A
// generated output can reuse recorded bytes without reusing their arrival.
type NetworkPlanner struct {
	evidence      *Evidence
	summary       NetworkSummary
	bindings      map[Question][]string
	byIdentity    map[string][]Question
	claimed       map[Question]bool
	slots         map[Source][]Question
	originalEntry map[Source]string
	sequence      uint64
}

func (e *Evidence) NewNetworkPlanner(bindings []NetworkBinding, scope NetworkScope) *NetworkPlanner {
	p := &NetworkPlanner{evidence: e, summary: NetworkSummary{Version: NetworkVersion, Status: "running", Scope: scope, Bindings: int64(len(bindings))}, bindings: map[Question][]string{}, byIdentity: map[string][]Question{}, claimed: map[Question]bool{}, slots: map[Source][]Question{}, originalEntry: e.entryMonos}
	for index, b := range bindings {
		p.bindings[b.Original] = append(p.bindings[b.Original], strconv.Itoa(index+1))
	}
	for q, a := range e.actions {
		if a.Kind == "broadcast" || a.Kind == "relay" || a.Kind == "commit" {
			p.byIdentity[NetworkIntentIdentity(a)] = append(p.byIdentity[NetworkIntentIdentity(a)], q)
			p.slots[q.Source] = append(p.slots[q.Source], q)
		}
	}
	return p
}
func (p *NetworkPlanner) Note(s Step) ([]NetworkEffect, error) {
	out := []NetworkEffect{}
	rank := 0
	for _, a := range s.Actions {
		if a.Kind != "broadcast" && a.Kind != "relay" && a.Kind != "commit" {
			continue
		}
		position := &OutputPosition{s.Execution, a.Output, s.Mono}
		effect := NetworkEffect{Kind: "added", Status: "arrival_unproved", Current: position, ActionKind: a.Kind, PayloadSHA256: a.PayloadSHA256, Bindings: []string{}}
		candidates := p.byIdentity[NetworkIntentIdentity(a)]
		var root *Question
		if a.Application != nil && a.Kind == "commit" {
			q := *a.Application
			root = &q
		} else if a.SigningOutput != nil {
			q := *a.SigningOutput
			root = &q
		} else if s.Source != nil {
			local := []Question{}
			for _, q := range candidates {
				if q.Source == *s.Source {
					local = append(local, q)
				}
			}
			if len(local) == 1 {
				q := local[0]
				root = &q
			}
		}
		if root == nil && len(candidates) == 1 {
			q := candidates[0]
			root = &q
		}
		effect.OriginCandidates = len(candidates)
		if root != nil {
			effect.Original = root
			effect.Bindings = p.bindings[*root]
			if effect.Bindings == nil {
				effect.Bindings = []string{}
			}
			effect.Kind = "relocated"
			if p.claimed[*root] {
				effect.Kind = "additional_copy"
			} else {
				p.claimed[*root] = true
				if s.Source != nil && root.Source == *s.Source && p.originalEntry[*s.Source] == s.Mono && p.originalRank(*root) == rank {
					effect.Kind = "unchanged"
					effect.Status = "unchanged_under_model"
				}
			}
		} else if len(candidates) > 1 {
			effect.Status = "ambiguous_origin"
		}
		if a.Kind == "commit" && effect.Kind != "unchanged" {
			effect.Status = "application_delivery_unproved"
		}
		if a.PayloadEvidence == "unsigned_request" {
			effect.Status = "unsigned_request"
		}
		if a.RecipientEvidence == "unknown" {
			effect.Status = "unknown_membership"
		}
		if a.RecipientEvidence == "validator_set" && len(a.Recipients) == 0 {
			effect.Status = "no_eligible_recipient"
		}
		if a.PayloadEvidence == "recorded_signing_failure" {
			effect.Status = "recorded_signing_failure"
		}
		if err := p.number(&effect); err != nil {
			return nil, err
		}
		out = append(out, effect)
		rank++
	}
	return out, nil
}
func (p *NetworkPlanner) originalRank(q Question) int {
	xs := append([]Question(nil), p.slots[q.Source]...)
	sort.Slice(xs, func(i, j int) bool {
		a, _ := strconv.ParseUint(xs[i].Output, 10, 64)
		b, _ := strconv.ParseUint(xs[j].Output, 10, 64)
		return a < b
	})
	for index, v := range xs {
		if v == q {
			return index
		}
	}
	return -1
}
func (p *NetworkPlanner) number(effect *NetworkEffect) error {
	if p.sequence >= 1000000 {
		return ErrEvidence
	}
	p.sequence++
	effect.ID = strconv.FormatUint(p.sequence, 10)
	p.summary.Effects++
	if effect.Kind == "unchanged" && effect.Status == "unchanged_under_model" {
		p.summary.Unchanged++
	} else if effect.Status != "no_eligible_recipient" && effect.Status != "recorded_signing_failure" {
		p.summary.Changed++
		if effect.Status != "observed_original_delivery" {
			p.summary.Unproved++
		}
		if effect.Current != nil && effect.Status != "no_eligible_recipient" && effect.Status != "recorded_signing_failure" && p.summary.FirstUnproved == nil {
			v := *effect.Current
			p.summary.FirstUnproved = &v
		}
	}
	return nil
}
func (p *NetworkPlanner) Finish(complete bool, bindings []NetworkBinding) ([]NetworkEffect, NetworkSummary, error) {
	out := []NetworkEffect{}
	if complete {
		roots := []Question{}
		for _, slots := range p.slots {
			for _, q := range slots {
				if !p.claimed[q] {
					roots = append(roots, q)
				}
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
		for _, q := range roots {
			a := p.evidence.actions[q]
			effect := NetworkEffect{Kind: "removed", Status: "original_delivery_unproved", Original: &q, ActionKind: a.Kind, PayloadSHA256: a.PayloadSHA256, Bindings: p.bindings[q]}
			if effect.Bindings == nil {
				effect.Bindings = []string{}
			}
			observed, inactive := 0, 0
			for _, id := range effect.Bindings {
				index, _ := strconv.Atoi(id)
				b := bindings[index-1]
				if b.Status == "no_eligible_recipient" || b.Status == "recorded_signing_failure" {
					inactive++
				}
				if b.Status == "observed_delivery" {
					observed++
					effect.Status = "observed_original_delivery"
					if p.summary.ObservedRemovedArrival == nil || arrivalBefore(b.Arrival, p.summary.ObservedRemovedArrival) {
						v := *b.Arrival
						p.summary.ObservedRemovedArrival = &v
					}
				}
			}
			if observed > 0 && observed+inactive < len(effect.Bindings) {
				effect.Status = "partly_observed_original_delivery"
			}
			if len(effect.Bindings) > 0 && inactive == len(effect.Bindings) {
				effect.Status = "no_eligible_recipient"
			}

			if err := p.number(&effect); err != nil {
				return nil, p.summary, err
			}
			out = append(out, effect)
		}
	}
	p.summary.Status = "unproved"
	if complete && p.summary.FirstUnproved == nil && p.summary.Changed == 0 && p.summary.Scope.Status == "complete" {
		p.summary.Status = "unchanged_under_model"
	}
	// A known original receive is conditional on the declared clock/source
	// scope. It is not the earliest influence if any new arrival is unproved.
	if complete && p.summary.Unproved == 0 && p.summary.FirstUnproved == nil && p.summary.ObservedRemovedArrival != nil && p.summary.Scope.Status == "complete" {
		p.summary.Status = "bounded_original_delivery"
	}
	return out, p.summary, nil
}

func (s *NetworkScope) Seal() {
	copyScope := *s
	copyScope.SHA256 = ""
	raw, _ := json.Marshal(copyScope)
	s.SHA256 = fingerprint(raw)
}

func arrivalBefore(a, b *ArrivalInterval) bool {
	x, e1 := time.Parse(time.RFC3339Nano, a.From)
	y, e2 := time.Parse(time.RFC3339Nano, b.From)
	return e1 == nil && e2 == nil && x.Before(y)
}
