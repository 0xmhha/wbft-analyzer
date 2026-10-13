package messages

import (
	"encoding/json"
	"sort"
	"time"
)

type SeriesPoint struct {
	At     string  `json:"at"`
	Height string  `json:"height"`
	Round  string  `json:"round"`
	Groups []Group `json:"groups"`
}
type TimeSeries struct {
	Points        []SeriesPoint `json:"points"`
	Pairs         int64         `json:"pairs"`
	BucketSeconds int64         `json:"bucket_seconds"`
	Method        string        `json:"method"`
}

// Series aggregates original pairs in fixed UTC buckets. Every boundary and
// evidence dimension remains in the nested groups; empty buckets are absent,
// not interpolated into measurements. Heights/rounds remain decimal strings.
func Series(pairs []Pair, bucketSeconds int64) TimeSeries {
	groups := map[[3]string][]Pair{}
	out := TimeSeries{Points: []SeriesPoint{}, Pairs: int64(len(pairs)), BucketSeconds: bucketSeconds, Method: "UTC fixed buckets; raw valid pairs; no interpolation of missing buckets"}
	if bucketSeconds < 1 || bucketSeconds > 3600 {
		return out
	}
	for _, p := range pairs {
		t, e := time.Parse(time.RFC3339Nano, p.At)
		if e != nil {
			continue
		}
		at := t.UTC().Truncate(time.Duration(bucketSeconds) * time.Second).Format(time.RFC3339Nano)
		groups[[3]string{at, p.Height, p.Round}] = append(groups[[3]string{at, p.Height, p.Round}], p)
	}
	keys := [][3]string{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, _ := json.Marshal(keys[i])
		b, _ := json.Marshal(keys[j])
		return string(a) < string(b)
	})
	for _, k := range keys {
		out.Points = append(out.Points, SeriesPoint{At: k[0], Height: k[1], Round: k[2], Groups: Summarize(groups[k]).Groups})
	}
	return out
}
