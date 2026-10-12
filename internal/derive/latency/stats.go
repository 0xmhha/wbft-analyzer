package latency

import (
	"math"
	"sort"
)

type Bucket struct {
	From  float64 `json:"from_seconds"`
	To    float64 `json:"to_seconds"`
	Count int64   `json:"count"`
}
type Stats struct {
	Node         string   `json:"node"`
	Profile      string   `json:"profile"`
	Metric       string   `json:"metric"`
	Clock        string   `json:"clock"`
	Total        int64    `json:"total"`
	Valid        int64    `json:"valid"`
	Missing      int64    `json:"missing"`
	Negative     int64    `json:"negative"`
	InvalidClock int64    `json:"invalid_clock"`
	Min          *float64 `json:"min_seconds"`
	Max          *float64 `json:"max_seconds"`
	Mean         *float64 `json:"mean_seconds"`
	Stddev       *float64 `json:"stddev_seconds"`
	P50          *float64 `json:"p50_seconds"`
	P90          *float64 `json:"p90_seconds"`
	P95          *float64 `json:"p95_seconds"`
	P99          *float64 `json:"p99_seconds"`
	Histogram    []Bucket `json:"histogram"`
}
type Summary struct {
	Groups  []Stats `json:"groups"`
	Method  string  `json:"percentile_method"`
	Samples int64   `json:"samples"`
}

// Distribution computes counts and quantiles from original samples. Callers
// keep their evidence dimensions outside this distribution; precomputed pair
// percentiles are never accepted as samples.
func Distribution(samples []Sample) Stats { return statistics([4]string{}, samples) }

func Summarize(samples []Sample) Summary {
	groups := map[[4]string][]Sample{}
	for _, s := range samples {
		groups[[4]string{s.Node, s.Profile, s.Metric, s.Clock}] = append(groups[[4]string{s.Node, s.Profile, s.Metric, s.Clock}], s)
		groups[[4]string{"", "", s.Metric, s.Clock}] = append(groups[[4]string{"", "", s.Metric, s.Clock}], s)
	}
	keys := [][4]string{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		for p := range 4 {
			if keys[i][p] != keys[j][p] {
				return keys[i][p] < keys[j][p]
			}
		}
		return false
	})
	out := Summary{Groups: []Stats{}, Method: "nearest_rank; population standard deviation; overall uses raw valid samples", Samples: int64(len(samples))}
	for _, k := range keys {
		out.Groups = append(out.Groups, statistics(k, groups[k]))
	}
	return out
}
func statistics(k [4]string, samples []Sample) Stats {
	out := Stats{Node: k[0], Profile: k[1], Metric: k[2], Clock: k[3], Histogram: []Bucket{}}
	xs := []float64{}
	for _, s := range samples {
		out.Total++
		switch s.Status {
		case "valid":
			if s.Seconds != nil {
				xs = append(xs, *s.Seconds)
				out.Valid++
			}
		case "negative":
			out.Negative++
		case "invalid_clock":
			out.InvalidClock++
		default:
			out.Missing++
		}
	}
	if len(xs) == 0 {
		return out
	}
	sort.Float64s(xs)
	n := float64(len(xs))
	mean := 0.0
	for _, v := range xs {
		mean += v / n
	}
	variance := 0.0
	for _, v := range xs {
		delta := v - mean
		variance += delta * delta / n
	}
	out.Min = ptr(xs[0])
	out.Max = ptr(xs[len(xs)-1])
	out.Mean = ptr(mean)
	out.Stddev = ptr(math.Sqrt(variance))
	out.P50 = ptr(percentile(xs, .5))
	out.P90 = ptr(percentile(xs, .9))
	out.P95 = ptr(percentile(xs, .95))
	out.P99 = ptr(percentile(xs, .99))
	bins := 10
	if len(xs) < bins {
		bins = len(xs)
	}
	width := (xs[len(xs)-1] - xs[0]) / float64(bins)
	if width == 0 {
		out.Histogram = []Bucket{{xs[0], xs[0], int64(len(xs))}}
		return out
	}
	for i := range bins {
		out.Histogram = append(out.Histogram, Bucket{xs[0] + float64(i)*width, xs[0] + float64(i+1)*width, 0})
	}
	for _, v := range xs {
		i := int((v - xs[0]) / width)
		if i >= bins {
			i = bins - 1
		}
		out.Histogram[i].Count++
	}
	return out
}
func percentile(xs []float64, p float64) float64 {
	i := int(math.Ceil(float64(len(xs))*p)) - 1
	if i < 0 {
		i = 0
	}
	return xs[i]
}
func ptr(v float64) *float64 { return &v }
