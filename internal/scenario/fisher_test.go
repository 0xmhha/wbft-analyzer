package scenario

import (
	"math"
	"math/big"
	"testing"
)

// The oracle uses exact integer combinations instead of log factorials.
func exactFisher(a, b, c, d int64) float64 {
	n1, n2, k := a+b, c+d, a+c
	weight := func(x int64) *big.Int {
		return new(big.Int).Mul(new(big.Int).Binomial(n1, x), new(big.Int).Binomial(n2, k-x))
	}
	observed := weight(a)
	sum := new(big.Int)
	for x := max(int64(0), k-n2); x <= min(k, n1); x++ {
		w := weight(x)
		if w.Cmp(observed) <= 0 {
			sum.Add(sum, w)
		}
	}
	p, _ := new(big.Rat).SetFrac(sum, new(big.Int).Binomial(n1+n2, k)).Float64()
	return p
}

func TestFisherExactTables(t *testing.T) {
	for a := int64(0); a < 7; a++ {
		for b := int64(0); b < 7; b++ {
			for c := int64(0); c < 7; c++ {
				for d := int64(0); d < 7; d++ {
					if a+b+c+d == 0 {
						continue
					}
					got, err := FisherTwoSided(a, b, c, d)
					if err != nil {
						t.Fatal(err)
					}
					want := exactFisher(a, b, c, d)
					if math.Abs(got-want) > 1e-11 {
						t.Fatalf("%v got %.15g want %.15g", []int64{a, b, c, d}, got, want)
					}
				}
			}
		}
	}
	for _, tab := range [][4]int64{{140, 727, 67, 337}, {140, 727, 62, 348}, {140, 727, 69, 333}, {1, 9, 11, 3}, {0, 10000, 5000, 5000}} {
		got, err := FisherTwoSided(tab[0], tab[1], tab[2], tab[3])
		if err != nil {
			t.Fatal(err)
		}
		want := exactFisher(tab[0], tab[1], tab[2], tab[3])
		if math.Abs(got-want) > 1e-9 {
			t.Fatalf("large %v: %.15g/%.15g", tab, got, want)
		}
	}
	if _, err := FisherTwoSided(-1, 0, 0, 0); err == nil {
		t.Fatal("negative accepted")
	}
	if _, err := FisherTwoSided(0, 0, 0, 0); err == nil {
		t.Fatal("empty accepted")
	}
}
