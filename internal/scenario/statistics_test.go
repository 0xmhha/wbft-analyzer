package scenario

import (
	"math"
	"testing"
)

func TestBaselineRunHomogeneity(t *testing.T) {
	runs := []RoundCount{{15, 111}, {19, 109}, {17, 106}, {21, 109}, {20, 110}, {16, 110}, {14, 107}, {18, 105}}
	got, err := RunHomogeneity(runs)
	if err != nil {
		t.Fatal(err)
	}
	if got.DF != 7 || math.Abs(got.Statistic-2.85) > 0.01 || got.P < 0.89 || got.P > 0.91 || got.Dispersion == nil {
		t.Fatalf("baseline %+v", got)
	}
	varied, err := RunHomogeneity([]RoundCount{{0, 100}, {100, 100}})
	if err != nil {
		t.Fatal(err)
	}
	if varied.P >= 0.01 {
		t.Fatal("nonhomogeneous runs accepted")
	}
	for _, bad := range [][]RoundCount{nil, {{1, 0}}, {{2, 1}}, {{-1, 1}}} {
		if _, err := RunHomogeneity(bad); err == nil {
			t.Fatal("bad counts accepted")
		}
	}
	for _, r := range [][]RoundCount{{{0, 10}, {0, 20}}, {{10, 10}, {20, 20}}, {{3, 10}}} {
		got, err := RunHomogeneity(r)
		if err != nil || got.P != 1 || got.Dispersion != nil {
			t.Fatal("degenerate counts")
		}
	}
}

func TestGammaQAnalyticCases(t *testing.T) {
	for _, z := range []float64{0.001, 0.2, 1, 3, 10, 50} {
		if math.Abs(gammaQ(1, z)-math.Exp(-z)) > 1e-12 {
			t.Fatal("df2")
		}
		if math.Abs(gammaQ(0.5, z)-math.Erfc(math.Sqrt(z))) > 1e-12 {
			t.Fatal("df1")
		}
	}
}
