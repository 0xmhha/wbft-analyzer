package messages

import (
	"encoding/json"
	"sort"
)

func rank(strength string) int {
	switch strength {
	case "link":
		return 3
	case "node":
		return 2
	case "key":
		return 1
	}
	return 0
}

// MixEndpoints applies weakest-side matching and preserves repeated copies at
// the selected grade. A stronger observation replaces only the alternate
// lower-grade observation of that role, not repeated observations at its own
// grade. Byte and tuple measurements are not emitted twice for one direction.
func MixEndpoints(xs []Endpoint) []Endpoint {
	return MixProjection(xs).Endpoints
}

func MixProjection(xs []Endpoint) Projection {
	byDirection := map[[3]string][]Endpoint{}
	for _, x := range xs {
		byDirection[[3]string{x.Sender, x.Receiver, x.Phase}] = append(byDirection[[3]string{x.Sender, x.Receiver, x.Phase}], x)
	}
	projection := Projection{Endpoints: []Endpoint{}, Issues: []Issue{}, Counts: map[string]int64{}}
	out := []Endpoint{}
	for _, direction := range byDirection {
		weakScopes := map[[2]string]bool{}
		for _, x := range direction {
			if x.Strength == "key" {
				if a, b := low64(x.Height), low64(x.Round); a != "" && b != "" {
					weakScopes[[2]string{a, b}] = true
				}
			}
		}
		// Tuple grouping is needed only when one side lacks bytes. Preserve full
		// values alongside low64 so conflicts are still detected by PairEndpoints.
		groups := map[string][]Endpoint{}
		for _, x := range direction {
			identity := ""
			if x.Key != "" {
				identity = "bytes:" + x.Key
			}
			if x.Height != "" && x.Round != "" {
				a, b := low64(x.Height), low64(x.Round)
				if a != "" && b != "" && weakScopes[[2]string{a, b}] {
					raw, _ := json.Marshal([]string{a, b})
					identity = string(raw)
				}
			}
			if identity == "" {
				projection.Issues = append(projection.Issues, Issue{Source: x.Source, Reason: "missing_mixed_identity"})
				projection.Counts["missing_mixed_identity"]++
				continue
			}
			groups[identity] = append(groups[identity], x)
		}
		for _, candidates := range groups {
			send, receive := 0, 0
			for _, x := range candidates {
				if x.Role == "send" {
					send = max(send, rank(x.Strength))
				}
				if x.Role == "receive" {
					receive = max(receive, rank(x.Strength))
				}
			}
			grade := min(send, receive)
			if grade == 0 {
				grade = max(send, receive)
			}
			target := "key"
			if grade >= 3 {
				target = "link"
			} else if grade >= 2 {
				target = "node"
			}
			// A weaker observation with contradictory known bytes or a full
			// view is not an alternate of the stronger one. Retain all such
			// candidates so tuple ambiguity survives grade selection.
			bytes, views, digests := map[string]bool{}, map[string]bool{}, map[string]bool{}
			for _, x := range candidates {
				if x.Key != "" {
					bytes[x.Key] = true
				}
				if x.Height != "" && x.Round != "" {
					views[x.Height+":"+x.Round] = true
				}
				if x.Digest != "" {
					digests[x.Digest] = true
				}
			}
			conflict := len(bytes) > 1 || len(views) > 1 || len(digests) > 1
			selected := []Endpoint{}
			for _, x := range candidates {
				expected := send
				if x.Role == "receive" {
					expected = receive
				}
				if rank(x.Strength) != expected && !conflict {
					projection.Issues = append(projection.Issues, Issue{Source: x.Source, Reason: "alternate_grade_observation"})
					projection.Counts["alternate_grade_observation"]++
					continue
				}
				// A wire relay's peer is not the message origin in a weak
				// processing log. Byte evidence must identify the author before
				// its wire timestamp can be used for an origin-key measurement.
				if target == "key" && x.Strength == "link" && x.Source.Kind == "message" && (x.Author == "" || canonicalNode(x.Author) != canonicalNode(x.Sender)) {
					projection.Issues = append(projection.Issues, Issue{Source: x.Source, Reason: "relay_origin_unresolved"})
					projection.Counts["relay_origin_unresolved"]++
					continue
				}
				x.Strength = target
				selected = append(selected, x)
			}
			metric := "link"
			if target != "link" {
				metric = "propagation_processing"
				for _, x := range selected {
					if x.Role == "receive" && x.Source.Kind == "message" {
						metric = "broadcast_to_receipt"
					}
				}
			}
			for _, x := range selected {
				x.Metric = metric
				out = append(out, x)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := json.Marshal(out[i])
		b, _ := json.Marshal(out[j])
		return string(a) < string(b)
	})
	projection.Endpoints = out
	return projection
}
