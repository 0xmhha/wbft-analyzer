// Package messages pairs recorded WBFT message metadata. Matching strength
// and clock uncertainty are evidence properties, not consensus judgments.
package messages

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"sort"
	"strings"
	"time"
)

type Source struct {
	Association string  `json:"association,omitempty"`
	DatasetID   int64   `json:"dataset_id,omitempty"`
	Kind        string  `json:"kind,omitempty"`
	Input       string  `json:"input"`
	File        string  `json:"file,omitempty"`
	Ordinal     int64   `json:"ordinal"`
	Node        string  `json:"node"`
	Run         string  `json:"run"`
	Seq         string  `json:"seq,omitempty"`
	Wall        string  `json:"t_wall"`
	Mono        *string `json:"t_mono_ns,omitempty"`
	ClockSource string  `json:"clock_source,omitempty"`
	Offset      *int64  `json:"offset,omitempty"`
}

// Endpoint is an evidence adapter's closed projection. Sender/Receiver denote
// the wire nodes at link strength and the origin/processing nodes otherwise.
// Key tuples must already have full values retained alongside their low64 key.
type Endpoint struct {
	Author   string `json:"author,omitempty"`
	Metric   string `json:"metric,omitempty"`
	Source   Source `json:"source"`
	Role     string `json:"role"`
	Strength string `json:"strength"`
	Sender   string `json:"sender"`
	Receiver string `json:"receiver"`
	Phase    string `json:"phase"`
	Height   string `json:"height"`
	Round    string `json:"round"`
	Digest   string `json:"digest,omitempty"`
	Key      string `json:"dedup_key,omitempty"`
	Cause    string `json:"cause,omitempty"`
	Write    string `json:"write,omitempty"`
}
type Clock struct {
	Model  string
	SkewMS int64
}
type Pair struct {
	ObservedFrom      *string  `json:"observed_from"`
	ObservedTo        *string  `json:"observed_to"`
	Metric            string   `json:"metric"`
	ID                string   `json:"id"`
	At                string   `json:"at"`
	Key               string   `json:"dedup_key,omitempty"`
	Digest            string   `json:"digest,omitempty"`
	Cause             string   `json:"cause,omitempty"`
	Write             string   `json:"write,omitempty"`
	Sender            string   `json:"sender"`
	Receiver          string   `json:"receiver"`
	Phase             string   `json:"phase"`
	Height            string   `json:"height"`
	Round             string   `json:"round"`
	Strength          string   `json:"strength"`
	Path              string   `json:"path"`
	Status            string   `json:"status"`
	Clock             string   `json:"clock"`
	Send              *Source  `json:"send"`
	Receive           *Source  `json:"receive"`
	RawSeconds        *float64 `json:"raw_seconds"`
	Seconds           *float64 `json:"seconds"`
	Lower             *float64 `json:"lower_seconds"`
	Upper             *float64 `json:"upper_seconds"`
	SendCandidates    int      `json:"send_candidates"`
	ReceiveCandidates int      `json:"receive_candidates"`
	Candidates        []Source `json:"candidates"`
	Views             []View   `json:"views"`
}

type View struct {
	Height string `json:"height"`
	Round  string `json:"round"`
}
type key struct{ Sender, Receiver, Phase, Height, Round, Strength, Identity, Metric string }

// PairEndpoints requires a unique send and receive for an identity. Repeated
// writes or receives remain ambiguous: timestamp proximity cannot identify
// which copy crossed an undocumented stream boundary.
func PairEndpoints(xs []Endpoint, clock Clock) []Pair {
	groups := map[key][]Endpoint{}
	weakViews := map[[5]string]map[string]bool{}
	weakDigests := map[[5]string]map[string]bool{}
	weakBytes := map[[5]string]map[string]bool{}
	for _, x := range xs {
		if x.Role != "send" && x.Role != "receive" || x.Sender == "" || x.Receiver == "" {
			continue
		}
		identity := x.Key
		height, round := x.Height, x.Round
		switch x.Strength {
		case "link", "node":
			if identity == "" {
				continue
			}
			// Bytes identify the complete message. SEND events need not carry
			// a view; a view from a different engine snapshot is not substituted.
			height, round = "", ""
		case "key":
			identity = ""
			height = low64(height)
			round = low64(round)
			if height == "" || round == "" {
				continue
			}
		default:
			continue
		}
		if x.Strength == "key" {
			wk := [5]string{x.Sender, x.Receiver, x.Phase, height, round}
			if weakViews[wk] == nil {
				weakViews[wk] = map[string]bool{}
				weakDigests[wk] = map[string]bool{}
				weakBytes[wk] = map[string]bool{}
			}
			weakViews[wk][x.Height+":"+x.Round] = true
			if x.Digest != "" {
				weakDigests[wk][x.Digest] = true
			}
			if x.Key != "" {
				weakBytes[wk][x.Key] = true
			}
		}
		metric := x.Metric
		if metric == "" {
			metric = "link"
			if x.Strength != "link" {
				metric = "propagation_processing"
			}
		}
		k := key{x.Sender, x.Receiver, x.Phase, height, round, x.Strength, identity, metric}
		groups[k] = append(groups[k], x)
	}
	keys := []key{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return strings.Join([]string{a.Sender, a.Receiver, a.Phase, a.Height, a.Round, a.Strength, a.Identity, a.Metric}, "\x00") < strings.Join([]string{b.Sender, b.Receiver, b.Phase, b.Height, b.Round, b.Strength, b.Identity, b.Metric}, "\x00")
	})
	out := []Pair{}
	for _, k := range keys {
		sends, receives := []Endpoint{}, []Endpoint{}
		full := map[string]bool{}
		digests := map[string]bool{}
		for _, x := range groups[k] {
			if x.Digest != "" {
				digests[x.Digest] = true
			}
			if x.Height != "" && x.Round != "" {
				full[x.Height+":"+x.Round] = true
			}
			if x.Role == "send" {
				sends = append(sends, x)
			} else {
				receives = append(receives, x)
			}
		}
		p := Pair{Sender: k.Sender, Receiver: k.Receiver, Phase: k.Phase, Height: k.Height, Round: k.Round, Strength: k.Strength, Path: "direct", Status: "ambiguous", Clock: "unavailable", SendCandidates: len(sends), ReceiveCandidates: len(receives)}
		p.Metric = k.Metric
		if k.Strength != "link" {
			p.Path = "propagation_processing"
		}
		if k.Sender == k.Receiver {
			p.Path = "local"
		}
		raw, _ := json.Marshal(k)
		sum := sha256.Sum256(raw)
		p.ID = hex.EncodeToString(sum[:])
		p.Candidates = []Source{}
		p.Views = []View{}
		for v := range full {
			parts := strings.SplitN(v, ":", 2)
			p.Views = append(p.Views, View{parts[0], parts[1]})
		}
		sort.Slice(p.Views, func(i, j int) bool {
			if p.Views[i].Height != p.Views[j].Height {
				return p.Views[i].Height < p.Views[j].Height
			}
			return p.Views[i].Round < p.Views[j].Round
		})
		for _, x := range groups[k] {
			if at, e := time.Parse(time.RFC3339Nano, x.Source.Wall); e == nil {
				if p.ObservedFrom == nil {
					v := x.Source.Wall
					p.ObservedFrom = &v
				} else {
					old, _ := time.Parse(time.RFC3339Nano, *p.ObservedFrom)
					if at.Before(old) {
						v := x.Source.Wall
						p.ObservedFrom = &v
					}
				}
				if p.ObservedTo == nil {
					v := x.Source.Wall
					p.ObservedTo = &v
				} else {
					old, _ := time.Parse(time.RFC3339Nano, *p.ObservedTo)
					if at.After(old) {
						v := x.Source.Wall
						p.ObservedTo = &v
					}
				}
			}
			p.Candidates = append(p.Candidates, x.Source)
		}
		sort.Slice(p.Candidates, func(i, j int) bool {
			a, b := p.Candidates[i], p.Candidates[j]
			if a.Input != b.Input {
				return a.Input < b.Input
			}
			if a.File != b.File {
				return a.File < b.File
			}
			return a.Ordinal < b.Ordinal
		})
		if len(p.Candidates) > 0 {
			p.At = p.Candidates[0].Wall
		}
		if len(p.Candidates) > 16 {
			p.Candidates = p.Candidates[:16]
		}
		if len(sends) == 1 {
			x := sends[0]
			p.Send = &x.Source
			p.Cause = x.Cause
			p.Write = x.Write
			p.Key = x.Key
			p.Digest = x.Digest
			p.At = x.Source.Wall
			p.Height = x.Height
			p.Round = x.Round
		}
		if len(receives) == 1 {
			x := receives[0]
			p.Receive = &x.Source
			if p.Key == "" {
				p.Key = x.Key
			}
			if p.Digest == "" {
				p.Digest = x.Digest
			}
			if p.Send == nil || p.Height == "" {
				p.Height = x.Height
				p.Round = x.Round
			}
			if p.Send == nil {
				p.At = x.Source.Wall
			}
		}
		wk := [5]string{k.Sender, k.Receiver, k.Phase, k.Height, k.Round}
		if len(full) > 1 || len(digests) > 1 || k.Strength == "key" && (len(weakViews[wk]) > 1 || len(weakDigests[wk]) > 1 || len(weakBytes[wk]) > 1) {
			p.Status = "ambiguous"
			if len(full) > 1 {
				p.Height = ""
				p.Round = ""
			}
		} else if len(sends) == 0 {
			p.Status = "missing_send"
		} else if len(receives) == 0 {
			p.Status = "missing_receive"
		} else if len(sends) == 1 && len(receives) == 1 && (k.Strength != "key" || len(full) == 1) {
			a, b := sends[0], receives[0]
			p.Send = &a.Source
			p.Receive = &b.Source
			if a.Height != "" {
				p.Height = a.Height
				p.Round = a.Round
			}
			if k.Sender == k.Receiver {
				p.Path = "local"
			} else if k.Strength == "link" && a.Cause == "relay" {
				p.Path = "relay"
			} else if k.Strength != "link" {
				p.Path = "propagation_processing"
			}
			if k.Strength == "link" && a.Write != "ok" {
				p.Status = "unconfirmed_write"
			} else {
				measure(&p, clock)
			}
		}
		out = append(out, p)
	}
	return out
}
func low64(s string) string {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 || n.String() != s || len(s) > 156 {
		return ""
	}
	return new(big.Int).SetUint64(n.Uint64()).String()
}
func measure(p *Pair, c Clock) {
	var delta float64
	if p.Path == "local" {
		if p.Send.Run == "" || p.Send.Run != p.Receive.Run || p.Send.Node != p.Receive.Node || p.Send.Mono == nil || p.Receive.Mono == nil {
			p.Status = "missing_clock"
			return
		}
		p.Clock = "monotonic"
		a, oka := new(big.Int).SetString(*p.Send.Mono, 10)
		b, okb := new(big.Int).SetString(*p.Receive.Mono, 10)
		if !oka || !okb || !a.IsInt64() || !b.IsInt64() || a.Sign() < 0 || b.Sign() < 0 {
			p.Status = "invalid_clock"
			return
		}
		d := new(big.Int).Sub(b, a)
		v, _ := new(big.Float).SetInt(d).Float64()
		delta = v / 1e9
	} else {
		a, e1 := time.Parse(time.RFC3339Nano, p.Send.Wall)
		b, e2 := time.Parse(time.RFC3339Nano, p.Receive.Wall)
		if e1 != nil || e2 != nil {
			p.Status = "missing_clock"
			return
		}
		// time.Time.Sub saturates at about 292 years. Preserve the exact
		// nanosecond difference before converting the interval to seconds.
		d := new(big.Int).Sub(big.NewInt(b.Unix()), big.NewInt(a.Unix()))
		d.Mul(d, big.NewInt(1000000000))
		d.Add(d, big.NewInt(int64(b.Nanosecond()-a.Nanosecond())))
		v, _ := new(big.Float).SetInt(d).Float64()
		delta = v / 1e9
		p.Clock = c.Model
	}
	p.RawSeconds = &delta
	if p.Clock == "unknown" || p.Clock == "" {
		p.Status = "unknown_clock"
		return
	}
	bound := 0.0
	if p.Clock == "ntp" {
		if c.SkewMS < 0 || c.SkewMS > 86400000 {
			p.Status = "invalid_clock"
			return
		}
		bound = float64(c.SkewMS) / 1000
	}
	if p.Clock != "monotonic" && p.Clock != "ntp" && p.Clock != "shared-host" {
		p.Status = "invalid_clock"
		return
	}
	lo, hi := delta-bound, delta+bound
	p.Lower = &lo
	p.Upper = &hi
	if hi < 0 {
		p.Status = "negative"
		return
	}
	if lo < 0 {
		p.Status = "clock_overlap"
		return
	}
	p.Status = "valid"
	p.Seconds = &delta
}
