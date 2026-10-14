package scenario

import (
	"errors"
	"sort"
)

type DistributionPoint struct {
	Value      uint64  `json:"value,string"`
	Cumulative float64 `json:"cumulative"`
	Count      int     `json:"count"`
}

type SeedBand struct {
	Height  uint64 `json:"height,string"`
	Minimum uint64 `json:"minimum,string"`
	Median  uint64 `json:"median,string"`
	Maximum uint64 `json:"maximum,string"`
	Seeds   int    `json:"seeds"`
}

// RoundECDF consumes canonical heights from complete seed runs. Partial
// runs cannot make a distribution appear complete by dropping missing heights.
func RoundECDF(runs []SeedResult) ([]DistributionPoint, error) {
	if _, err := TimeBands(runs); err != nil {
		return nil, err
	}
	xs := []uint64{}
	seen := map[int64]bool{}
	for _, r := range runs {
		if seen[r.Seed] {
			return nil, errors.New("duplicate distribution seed")
		}
		seen[r.Seed] = true
		if r.Status != "complete" || len(r.Heights) == 0 {
			return nil, errors.New("round distribution requires complete seed runs")
		}
		for _, h := range r.Heights {
			xs = append(xs, h.Round)
		}
	}
	if len(xs) == 0 || len(xs) > 1280000 {
		return nil, errors.New("invalid round distribution size")
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	out := []DistributionPoint{}
	for i := 0; i < len(xs); {
		j := i + 1
		for j < len(xs) && xs[j] == xs[i] {
			j++
		}
		out = append(out, DistributionPoint{Value: xs[i], Cumulative: float64(j) / float64(len(xs)), Count: j - i})
		i = j
	}
	return out, nil
}

// TimeBands show elapsed header time by height for the same height scope in
// every seed; they are descriptive ranges, not a made-up acceptance threshold.
func TimeBands(runs []SeedResult) ([]SeedBand, error) {
	if len(runs) == 0 || len(runs) > 128 {
		return nil, errors.New("invalid seed bands")
	}
	bins := map[uint64][]uint64{}
	scope := []uint64{}
	seeds := map[int64]bool{}
	for i, r := range runs {
		if seeds[r.Seed] {
			return nil, errors.New("duplicate band seed")
		}
		seeds[r.Seed] = true
		if r.Status != "complete" || len(r.Heights) == 0 {
			return nil, errors.New("time bands require complete seed runs")
		}
		seen := map[uint64]bool{}
		start := r.Heights[0].Time
		for j, h := range r.Heights {
			if seen[h.Number] || h.Time < start || i > 0 && (j >= len(scope) || scope[j] != h.Number) {
				return nil, errors.New("seed height scope or time mismatch")
			}
			seen[h.Number] = true
			if i == 0 {
				scope = append(scope, h.Number)
			}
			bins[h.Number] = append(bins[h.Number], h.Time-start)
		}
		if len(r.Heights) != len(scope) {
			return nil, errors.New("seed height scope mismatch")
		}
	}
	out := []SeedBand{}
	for _, h := range scope {
		xs := bins[h]
		sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
		out = append(out, SeedBand{Height: h, Minimum: xs[0], Median: xs[(len(xs)-1)/2], Maximum: xs[len(xs)-1], Seeds: len(xs)})
	}
	return out, nil
}

// PeriodECDF reports per-height header intervals, separate from elapsed bands.
// Header timestamps have integer-second resolution; no finer timing is inferred.
func PeriodECDF(runs []SeedResult) ([]DistributionPoint, error) {
	if _, err := TimeBands(runs); err != nil {
		return nil, err
	}
	copies := make([]SeedResult, len(runs))
	for i, r := range runs {
		copies[i] = r
		copies[i].Heights = append([]Height(nil), r.Heights...)
		for j, h := range r.Heights {
			copies[i].Heights[j].Round = h.PeriodSeconds
		}
	}
	return RoundECDF(copies)
}
