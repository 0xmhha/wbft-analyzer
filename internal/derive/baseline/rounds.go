// Package baseline compares independent run observations, never pooled node claims.
package baseline

import (
	"math"
	"math/big"
	"sort"
)

type Bin struct {
	Round string `json:"round"`
	Count int64  `json:"count"`
}
type Observer struct {
	Node    string `json:"node"`
	Profile string `json:"profile"`
	Known   int64  `json:"known"`
	Unknown int64  `json:"unknown"`
	Missing int64  `json:"missing"`
	Bins    []Bin  `json:"bins"`
}
type Input struct {
	ID      string `json:"id"`
	Node    string `json:"node"`
	Profile string `json:"profile"`
	SHA256  string `json:"sha256"`
}
type Run struct {
	Dataset   int64      `json:"dataset"`
	Name      string     `json:"name"`
	Inputs    []Input    `json:"inputs"`
	Observers []Observer `json:"observers"`
}
type Rate struct {
	Dataset     int64    `json:"dataset"`
	Count       int64    `json:"count"`
	Denominator int64    `json:"denominator"`
	Fraction    *float64 `json:"fraction"`
}
type Comparison struct {
	Node     string   `json:"node"`
	Profile  string   `json:"profile"`
	Round    string   `json:"round"`
	Runs     int      `json:"runs"`
	Samples  []Rate   `json:"samples"`
	Mean     *float64 `json:"mean_fraction"`
	Variance *float64 `json:"sample_variance"`
	Stddev   *float64 `json:"sample_stddev"`
}
type Summary struct {
	From        string       `json:"from"`
	To          string       `json:"to"`
	Expected    int64        `json:"expected_heights"`
	Runs        []Run        `json:"runs"`
	Comparisons []Comparison `json:"comparisons"`
	Method      string       `json:"method"`
}

func Compare(runs []Run) []Comparison {
	keys := map[[3]string]bool{}
	for _, r := range runs {
		for _, o := range r.Observers {
			keys[[3]string{o.Node, o.Profile, "0"}] = true
			for _, b := range o.Bins {
				keys[[3]string{o.Node, o.Profile, b.Round}] = true
			}
		}
	}
	sorted := [][3]string{}
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Slice(sorted, func(i, j int) bool {
		for n := range 2 {
			if sorted[i][n] != sorted[j][n] {
				return sorted[i][n] < sorted[j][n]
			}
		}
		a, _ := new(big.Int).SetString(sorted[i][2], 10)
		b, _ := new(big.Int).SetString(sorted[j][2], 10)
		return a.Cmp(b) < 0
	})
	out := []Comparison{}
	for _, k := range sorted {
		c := Comparison{Node: k[0], Profile: k[1], Round: k[2], Samples: []Rate{}}
		xs := []float64{}
		for _, r := range runs {
			rate := Rate{Dataset: r.Dataset}
			for _, o := range r.Observers {
				if o.Node == k[0] && o.Profile == k[1] {
					rate.Denominator = o.Known
					for _, b := range o.Bins {
						if b.Round == k[2] {
							rate.Count = b.Count
						}
					}
					if o.Known > 0 {
						value := float64(rate.Count) / float64(o.Known)
						rate.Fraction = &value
						xs = append(xs, value)
					}
				}
			}
			c.Samples = append(c.Samples, rate)
		}
		c.Runs = len(xs)
		if len(xs) > 0 {
			mean := 0.0
			for _, x := range xs {
				mean += x / float64(len(xs))
			}
			c.Mean = &mean
			if len(xs) > 1 {
				variance := 0.0
				for _, x := range xs {
					variance += (x - mean) * (x - mean) / float64(len(xs)-1)
				}
				stddev := math.Sqrt(variance)
				c.Variance = &variance
				c.Stddev = &stddev
			}
		}
		out = append(out, c)
	}
	return out
}
