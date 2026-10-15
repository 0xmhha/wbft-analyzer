package scenario

import (
	"errors"
	"math/rand/v2"
)

// runCDFProbability permutes complete runs. A common height scope makes the
// CDF statistic an exact integer numerator, including ties and large intervals.
func runCDFProbability(a, b [][]int64, seed uint64) (ConditionalProbability, error) {
	out := ConditionalProbability{Method: "whole_run_cdf/permutation_exact", Exact: true, Seed: seed}
	if len(a) < 2 || len(b) < 2 || len(a)+len(b) > 256 || len(a[0]) == 0 {
		return out, errors.New("invalid whole-run interval permutation")
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	xs := append(append([][]int64(nil), a...), b...)
	width := len(a[0])
	prefix := make([][]int64, len(xs))
	total := make([]int64, width)
	var samples int64
	for i, row := range xs {
		if len(row) != width {
			return out, errors.New("ragged interval run histogram")
		}
		prefix[i] = make([]int64, width)
		var cumulative int64
		for j, n := range row {
			if n < 0 || n > 10000 || cumulative > 10000-n {
				return out, errors.New("invalid interval run count")
			}
			cumulative += n
			prefix[i][j] = cumulative
			total[j] += cumulative
		}
		if i == 0 {
			samples = cumulative
		}
		if cumulative == 0 || cumulative != samples {
			return out, errors.New("interval permutation needs a common height scope")
		}
	}
	n := len(a)
	sums := make([]int64, width)
	statistic := func() int64 {
		var maximum int64
		for j, sum := range sums {
			x := sum*int64(len(xs)) - total[j]*int64(n)
			if x < 0 {
				x = -x
			}
			maximum = max(maximum, x)
		}
		return maximum
	}
	for _, row := range prefix[:n] {
		for j, v := range row {
			sums[j] += v
		}
	}
	observed := statistic()
	clear(sums)
	if observed == 0 {
		out.Method = "whole_run_cdf/exact_zero_distance"
		p := 1.0
		out.P = &p
		out.Lower = 1
		out.Upper = 1
		out.Samples = 1
		return out, nil
	}
	work := int64((n+1)*width + len(xs))
	limit := int(min(int64(tableSampleLimit), tableWorkLimit/work))
	if limit == 0 {
		out.Exact = false
		out.Upper = 1
		out.Issue = "interval_permutation_work_limit"
		return out, nil
	}
	count := 1.0
	for i := 1; i <= n; i++ {
		count *= float64(len(xs)-i+1) / float64(i)
		if count > float64(limit) {
			break
		}
	}
	hits := 0
	if count <= float64(limit) {
		var visit func(int, int)
		visit = func(start, left int) {
			if left == 0 {
				out.Samples++
				if statistic() >= observed {
					hits++
				}
				return
			}
			for i := start; i <= len(xs)-left; i++ {
				for j, v := range prefix[i] {
					sums[j] += v
				}
				visit(i+1, left-1)
				for j, v := range prefix[i] {
					sums[j] -= v
				}
			}
		}
		visit(0, n)
		p := float64(hits) / float64(out.Samples)
		out.P = &p
		out.Lower = p
		out.Upper = p
		return out, nil
	}
	out.Method = "whole_run_cdf/permutation_monte_carlo"
	out.Exact = false
	out.ErrorProbability = tableErrorProbability
	out.Samples = limit
	rng := rand.New(rand.NewPCG(seed, 0x696e74657276616c))
	indexes := make([]int, len(xs))
	for i := range indexes {
		indexes[i] = i
	}
	for range limit {
		clear(sums)
		for i := range n {
			j := i + rng.IntN(len(xs)-i)
			indexes[i], indexes[j] = indexes[j], indexes[i]
			for k, v := range prefix[indexes[i]] {
				sums[k] += v
			}
		}
		if statistic() >= observed {
			hits++
		}
	}
	p := float64(hits+1) / float64(limit+1)
	out.P = &p
	out.Lower, out.Upper = bernoulliTailBounds(hits, limit, tableErrorProbability)
	return out, nil
}
