package scenario

import (
	"math"
	"math/big"
	"math/bits"
	"reflect"
	"testing"
)

func TestWholeRunCDFPermutationAgainstRationalEnumeration(t *testing.T) {
	a := [][]int64{{2, 3, 3}, {5, 1, 2}}
	b := [][]int64{{0, 4, 4}, {1, 1, 6}, {4, 3, 1}, {3, 3, 2}}
	xs := append(append([][]int64{}, a...), b...)
	n := len(a)
	distance := func(mask uint64) *big.Rat {
		maximum := new(big.Rat)
		for column := range a[0] {
			left, right := int64(0), int64(0)
			for i, row := range xs {
				for _, v := range row[:column+1] {
					if mask&(1<<i) != 0 {
						left += v
					} else {
						right += v
					}
				}
			}
			l := new(big.Rat).SetFrac64(left, int64(n*8))
			r := new(big.Rat).SetFrac64(right, int64(len(b)*8))
			l.Sub(l, r)
			l.Abs(l)
			if l.Cmp(maximum) > 0 {
				maximum.Set(l)
			}
		}
		return maximum
	}
	observed := distance((1 << n) - 1)
	hits, total := int64(0), int64(0)
	for mask := uint64(0); mask < 1<<len(xs); mask++ {
		if bits.OnesCount64(mask) != n {
			continue
		}
		total++
		if distance(mask).Cmp(observed) >= 0 {
			hits++
		}
	}
	want := float64(hits) / float64(total)
	got, err := runCDFProbability(a, b, 7)
	if err != nil || !got.Exact || got.P == nil || *got.P != want || got.Samples != int(total) {
		t.Fatalf("per-run CDF labels differ from rational oracle: %+v %v want %g", got, err, want)
	}
}

func TestWholeRunCDFSamplingKeepsRareTailAndReproducibility(t *testing.T) {
	a, b := make([][]int64, 12), make([][]int64, 12)
	for i := range a {
		a[i] = []int64{8, 0}
		b[i] = []int64{0, 8}
	}
	got, err := runCDFProbability(a, b, 13)
	ways := new(big.Int).Binomial(24, 12)
	p, _ := new(big.Rat).SetFrac(big.NewInt(2), ways).Float64()
	if err != nil || got.Exact || got.P == nil || *got.P <= 0 || got.Upper >= baselineAlpha || p < got.Lower || p > got.Upper {
		t.Fatalf("sampled run tails lost uncertainty: %+v %v exact %g", got, err, p)
	}
	again, err := runCDFProbability(a, b, 13)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("permutation not reproducible", err)
	}
}

func TestWholeRunCDFRejectsMismatchedSamplingUnits(t *testing.T) {
	for _, test := range []struct{ a, b [][]int64 }{
		{[][]int64{{1, 2}}, [][]int64{{1, 2}, {2, 1}}},
		{[][]int64{{1, 2}, {2, 1}}, [][]int64{{1, 3}, {2, 1}}},
		{[][]int64{{1, 2}, {2, 1}}, [][]int64{{1}, {2, 1}}},
		{[][]int64{{-1, 4}, {2, 1}}, [][]int64{{1, 2}, {2, 1}}},
	} {
		if _, err := runCDFProbability(test.a, test.b, 1); err == nil {
			t.Fatal("invalid run unit accepted")
		}
	}
	lo, hi := bernoulliTailBounds(100, 1000, tableErrorProbability)
	if math.IsNaN(lo) || math.IsNaN(hi) || lo >= .1 || hi <= .1 {
		t.Fatal("invalid fixed-sample confidence bound")
	}
}
