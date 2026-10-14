package scenario

import (
	"errors"
	"math"
	"math/rand/v2"
)

type Permutation struct {
	P      float64 `json:"p"`
	Exact  bool    `json:"exact"`
	Splits int     `json:"splits"`
	Seed   uint64  `json:"seed,string"`
}

// RunPermutation compares unweighted per-run late shares. It enumerates all
// splits when bounded; otherwise it records a deterministic sampled estimate.
func RunPermutation(a, b []RoundCount, seed uint64) (Permutation, error) {
	if len(a) < 2 || len(b) < 2 || len(a)+len(b) > 128 {
		return Permutation{}, errors.New("permutation needs bounded independent runs")
	}
	xs := []float64{}
	for _, rs := range [][]RoundCount{a, b} {
		for _, r := range rs {
			if r.Total <= 0 || r.Total > 1000000 || r.Late < 0 || r.Late > r.Total {
				return Permutation{}, errors.New("invalid permutation counts")
			}
			xs = append(xs, float64(r.Late)/float64(r.Total))
		}
	}
	n := len(a)
	total, sa := 0.0, 0.0
	for i, x := range xs {
		total += x
		if i < n {
			sa += x
		}
	}
	diff := func(sum float64) float64 { return math.Abs(sum/float64(n) - (total-sum)/float64(len(b))) }
	observed := diff(sa)
	const limit = 200000
	count := 1.0
	for i := 1; i <= min(n, len(b)); i++ {
		count *= float64(len(xs)-i+1) / float64(i)
		if count > limit {
			break
		}
	}
	out := Permutation{Seed: seed}
	hits := 0
	if count <= limit {
		out.Exact = true
		var visit func(int, int, float64)
		visit = func(start, left int, sum float64) {
			if left == 0 {
				out.Splits++
				if diff(sum) >= observed-1e-12 {
					hits++
				}
				return
			}
			for i := start; i <= len(xs)-left; i++ {
				visit(i+1, left-1, sum+xs[i])
			}
		}
		visit(0, n, 0)
		out.P = float64(hits) / float64(out.Splits)
	} else {
		rng := rand.New(rand.NewPCG(seed, 0x7363656e6172696f))
		indexes := make([]int, len(xs))
		for i := range indexes {
			indexes[i] = i
		}
		out.Splits = limit
		for range limit {
			sum := 0.0
			for i := range n {
				j := i + rng.IntN(len(xs)-i)
				indexes[i], indexes[j] = indexes[j], indexes[i]
				sum += xs[indexes[i]]
			}
			if diff(sum) >= observed-1e-12 {
				hits++
			}
		}
		out.P = float64(hits+1) / float64(limit+1)
	}
	return out, nil
}
