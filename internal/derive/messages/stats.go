package messages

import (
	"encoding/json"
	"github.com/0xmhha/wbft-analyzer/internal/derive/latency"
	"sort"
)

type GroupKey struct {
	Metric   string `json:"metric"`
	Scope    string `json:"scope"`
	Sender   string `json:"sender"`
	Receiver string `json:"receiver"`
	Node     string `json:"node"`
	Phase    string `json:"phase"`
	Strength string `json:"strength"`
	Path     string `json:"path"`
	Clock    string `json:"clock"`
}
type Group struct {
	Key          GroupKey         `json:"key"`
	Statuses     map[string]int64 `json:"statuses"`
	Distribution latency.Stats    `json:"distribution"`
}
type PairStatistics struct {
	Groups []Group `json:"groups"`
	Pairs  int64   `json:"pairs"`
	Method string  `json:"percentile_method"`
}

// Summarize keeps direction, phase, matching strength, path and clock apart.
// Overall and node groups are independently calculated from original pairs.
// Unknown-clock raw trends never enter valid distributions or rankings.
func Summarize(pairs []Pair) PairStatistics {
	grouped := map[GroupKey][]Pair{}
	for _, p := range pairs {
		common := GroupKey{Phase: p.Phase, Strength: p.Strength, Path: p.Path, Clock: p.Clock, Metric: p.Metric}
		k := common
		k.Scope = "overall"
		grouped[k] = append(grouped[k], p)
		k = common
		k.Scope = "direction"
		k.Sender = p.Sender
		k.Receiver = p.Receiver
		grouped[k] = append(grouped[k], p)
		k = common
		k.Scope = "node_out"
		k.Node = p.Sender
		grouped[k] = append(grouped[k], p)
		k = common
		k.Scope = "node_in"
		k.Node = p.Receiver
		grouped[k] = append(grouped[k], p)
	}
	keys := []GroupKey{}
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, _ := json.Marshal(keys[i])
		b, _ := json.Marshal(keys[j])
		return string(a) < string(b)
	})
	out := PairStatistics{Groups: []Group{}, Pairs: int64(len(pairs)), Method: "nearest_rank; population standard deviation; raw valid pairs only; evidence dimensions separated"}
	for _, k := range keys {
		g := Group{Key: k, Statuses: map[string]int64{}}
		samples := []latency.Sample{}
		for _, p := range grouped[k] {
			g.Statuses[p.Status]++
			samples = append(samples, latency.Sample{Status: p.Status, Seconds: p.Seconds})
		}
		g.Distribution = latency.Distribution(samples)
		out.Groups = append(out.Groups, g)
	}
	return out
}
