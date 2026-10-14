// Package scenario fits simulation inputs from explicitly scoped observations.
package scenario

import (
	"fmt"
	"math"
	"sort"
	"time"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
)

const FitVersion = "wbft-network-scenario-fit/6"

func ValidWireMetric(metric string) bool {
	return metric == "link" || metric == pairs.WriteStartToReadComplete
}

// Coverage is an independently verified continuous receiver recording window.
// It must not be inferred from the existence of one received message.
type Coverage struct {
	Node string    `json:"node"`
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// SettledThrough certifies that sends up to this time had a completed
	// observation horizon. It is not inferred from the last receipt.
	SettledThrough time.Time `json:"settled_through"`
	Complete       bool      `json:"complete"`
}

type Delay struct {
	Pair        string `json:"pair"`
	Nanoseconds int64  `json:"nanoseconds"`
	Lower       int64  `json:"lower_nanoseconds"`
	Upper       int64  `json:"upper_nanoseconds"`
}

type Link struct {
	Metric   string   `json:"metric"`
	Sender   string   `json:"sender"`
	Receiver string   `json:"receiver"`
	Delays   []Delay  `json:"delays"`
	Observed int64    `json:"observed"`
	Missing  int64    `json:"missing"`
	Unproved int64    `json:"unproved"`
	Loss     *float64 `json:"loss"`
	Status   string   `json:"status"`
}

// FitLinks excludes propagation/node matches, failed writes and ambiguous
// copies. Missing receipts contribute to loss only within a verified complete
// receiver interval; a missing file never implies packet loss.
func FitLinks(nodes []string, observations []pairs.Pair, coverage []Coverage, clock string, skew time.Duration) ([]Link, error) {
	return FitLinksMetric(nodes, observations, coverage, clock, skew, "link")
}

func FitLinksMetric(nodes []string, observations []pairs.Pair, coverage []Coverage, clock string, skew time.Duration, metric string) ([]Link, error) {
	if !ValidWireMetric(metric) {
		return nil, fmt.Errorf("unsupported wire measurement")
	}
	if len(nodes) < 2 || len(nodes) > 256 || skew < 0 {
		return nil, fmt.Errorf("invalid scenario link scope")
	}
	known := map[string]bool{}
	for _, n := range nodes {
		if n == "" || known[n] {
			return nil, fmt.Errorf("invalid scenario node")
		}
		known[n] = true
	}
	for _, c := range coverage {
		if !known[c.Node] || c.To.Before(c.From) || c.SettledThrough.Before(c.From) || c.SettledThrough.After(c.To) {
			return nil, fmt.Errorf("invalid receiver coverage")
		}
	}
	links := map[[2]string]*Link{}
	for _, a := range nodes {
		for _, b := range nodes {
			if a != b {
				links[[2]string{a, b}] = &Link{Metric: metric, Sender: a, Receiver: b, Delays: []Delay{}, Status: "unavailable"}
			}
		}
	}
	seen := map[string]bool{}
	for _, p := range observations {
		actual := p.Metric
		if actual == "" {
			actual = "link"
		}
		if actual != metric {
			continue
		}
		l := links[[2]string{p.Sender, p.Receiver}]
		if l == nil || p.Strength != "link" {
			continue
		}
		if p.ID == "" || seen[p.ID] {
			return nil, fmt.Errorf("duplicate or missing pair identity")
		}
		seen[p.ID] = true
		if metric == pairs.WriteStartToReadComplete && (p.Send != nil && p.Send.Moment != "write_start" || p.Receive != nil && p.Receive.Moment != "read_complete") {
			l.Unproved++
			continue
		}
		if p.Send == nil || p.SendCandidates != 1 || p.Write != "ok" || p.Send.Node != p.Sender || p.Receive != nil && p.Receive.Node != p.Receiver {
			l.Unproved++
			continue
		}
		send, err := time.Parse(time.RFC3339Nano, p.Send.Wall)
		if err != nil {
			l.Unproved++
			continue
		}
		covered := false
		for _, c := range coverage {
			if c.Node == p.Receiver && c.Complete && (clock == "shared-host" || clock == "ntp") && !send.Add(-skew).Before(c.From) && send.Add(skew).Before(c.SettledThrough) {
				covered = true
			}
		}
		if p.Status == "missing_receive" && p.ReceiveCandidates == 0 {
			if covered {
				l.Missing++
			} else {
				l.Unproved++
			}
			continue
		}
		if p.Status != "valid" || p.Receive == nil || p.ReceiveCandidates != 1 || (clock != "shared-host" && clock != "ntp") {
			l.Unproved++
			continue
		}
		receive, err := time.Parse(time.RFC3339Nano, p.Receive.Wall)
		if err != nil {
			l.Unproved++
			continue
		}
		d := receive.Sub(send)
		if d == time.Duration(math.MaxInt64) || d == time.Duration(math.MinInt64) {
			return nil, fmt.Errorf("delay outside duration domain")
		}
		if d < 0 {
			l.Unproved++
			continue
		}
		spread := time.Duration(0)
		if clock == "ntp" {
			spread = skew
		}
		if d > time.Duration(1<<63-1)-spread {
			return nil, fmt.Errorf("delay interval overflow")
		}
		lower := max(time.Duration(0), d-spread)
		if !covered {
			l.Unproved++
		}
		l.Delays = append(l.Delays, Delay{Pair: p.ID, Nanoseconds: int64(d), Lower: int64(lower), Upper: int64(d + spread)})
		l.Observed++
	}
	out := []Link{}
	for _, l := range links {
		sort.Slice(l.Delays, func(i, j int) bool { return l.Delays[i].Pair < l.Delays[j].Pair })
		if l.Observed > 0 {
			l.Status = "partial"
			covered := false
			for _, c := range coverage {
				if c.Node == l.Receiver && c.Complete && c.SettledThrough.After(c.From) {
					covered = true
				}
			}
			if l.Unproved == 0 && covered {
				l.Status = "complete"
				v := float64(l.Missing) / float64(l.Observed+l.Missing)
				l.Loss = &v
			}
		}
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sender != out[j].Sender {
			return out[i].Sender < out[j].Sender
		}
		return out[i].Receiver < out[j].Receiver
	})
	return out, nil
}
