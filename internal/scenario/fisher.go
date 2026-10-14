package scenario

import (
	"errors"
	"math"
)

// FisherTwoSided sums fixed-margin table probabilities no greater than the
// observed table probability. Counts are bounded for synchronous analysis.
func FisherTwoSided(a, b, c, d int64) (float64, error) {
	for _, n := range []int64{a, b, c, d} {
		if n < 0 || n > 1000000 {
			return 0, errors.New("invalid Fisher table count")
		}
	}
	n1, n2, k := a+b, c+d, a+c
	n := n1 + n2
	if n == 0 {
		return 0, errors.New("empty Fisher table")
	}
	choose := func(n, k int64) float64 {
		x, _ := math.Lgamma(float64(n + 1))
		y, _ := math.Lgamma(float64(k + 1))
		z, _ := math.Lgamma(float64(n - k + 1))
		return x - y - z
	}
	logp := func(x int64) float64 { return choose(n1, x) + choose(n2, k-x) - choose(n, k) }
	observed := logp(a)
	lo, hi := max(int64(0), k-n2), min(k, n1)
	// Sum with compensation. Working in log space avoids underflow in the
	// observed tail when counts are large; very small returned p may be zero.
	sum, correction := 0.0, 0.0
	for x := lo; x <= hi; x++ {
		p := logp(x)
		if p <= observed+math.Log1p(1e-9) {
			y := math.Exp(p) - correction
			next := sum + y
			correction = (next - sum) - y
			sum = next
		}
	}
	return min(1.0, sum), nil
}
