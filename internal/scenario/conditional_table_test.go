package scenario

import (
	"encoding/json"
	"math"
	"math/big"
	"os"
	"reflect"
	"testing"
)

type conditionalOracle struct {
	Table  [][]int64 `json:"table"`
	P      string    `json:"p"`
	Tables int       `json:"tables"`
}

func conditionalOracles(t *testing.T) []conditionalOracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/conditional-tables.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []conditionalOracle
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func oracleValue(t *testing.T, s string) float64 {
	t.Helper()
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		t.Fatal("invalid exact oracle")
	}
	x, _ := r.Float64()
	return x
}

func TestExactConditionalTablesAgainstRationalOracle(t *testing.T) {
	for _, test := range conditionalOracles(t)[:8] {
		before, err := json.Marshal(test.Table)
		if err != nil {
			t.Fatal(err)
		}
		got, err := fixedMarginProbability(test.Table, 17)
		want := oracleValue(t, test.P)
		if err != nil || !got.Exact || got.P == nil || math.Abs(*got.P-want) > 1e-11 || got.Samples != test.Tables {
			t.Fatalf("%v: %+v %v want %g/%d", test.Table, got, err, want, test.Tables)
		}
		after, err := json.Marshal(test.Table)
		if err != nil || string(before) != string(after) {
			t.Fatal("caller table mutated")
		}
		// Relabeling either margin cannot change the exact probability.
		reversed := make([][]int64, len(test.Table))
		for i, row := range test.Table {
			reversed[len(test.Table)-1-i] = make([]int64, len(row))
			for j, n := range row {
				reversed[len(test.Table)-1-i][len(row)-1-j] = n
			}
		}
		other, err := fixedMarginProbability(reversed, 9)
		if err != nil || other.P == nil || math.Abs(*other.P-want) > 1e-11 {
			t.Fatal("margin relabel changed probability", other, err)
		}
	}
}

func TestSampledConditionalTablesKeepBoundsAndSeed(t *testing.T) {
	for i, test := range conditionalOracles(t)[8:] {
		got, err := fixedMarginProbability(test.Table, 83)
		want := oracleValue(t, test.P)
		if err != nil || got.Exact || got.P == nil || *got.P <= 0 || *got.P > 1 || got.Samples < 1 || got.Samples > tableSampleLimit || got.Seed != 83 || got.ErrorProbability != tableErrorProbability {
			t.Fatalf("sample result %+v/%v", got, err)
		}
		if got.Lower > want || got.Upper < want {
			t.Fatalf("exact tail %g outside [%g,%g]", want, got.Lower, got.Upper)
		}
		if i == 0 && (got.Lower < .01 || *got.P != 1) {
			t.Fatal("maximal-mass table was rejected", got)
		}
		if i == 2 && got.Upper >= .01 {
			t.Fatal("rare tail should be distinguishable with its numerical bound", got)
		}
		if i == 1 {
			again, err := fixedMarginProbability(test.Table, 83)
			if err != nil || !reflect.DeepEqual(got, again) {
				t.Fatal("sampled result is not reproducible", err)
			}
		}
	}
}

func TestExactConditionalUnderflowIsExplicit(t *testing.T) {
	got, err := fixedMarginProbability([][]int64{{5000, 0}, {0, 5000}}, 1)
	if err != nil || !got.Exact || !got.Underflow || got.P == nil || *got.P != 0 || got.LogP == nil || math.IsInf(*got.LogP, 0) || got.Upper != math.SmallestNonzeroFloat64 {
		t.Fatalf("underflow hidden: %+v %v", got, err)
	}
	a, _ := math.Lgamma(10001)
	b, _ := math.Lgamma(5001)
	want := math.Log(2) - (a - 2*b)
	if math.Abs(*got.LogP-want) > 1e-7 {
		t.Fatalf("log probability %g want %g", *got.LogP, want)
	}
}

func TestConditionalTableDegeneracyAndInvalidCounts(t *testing.T) {
	for _, table := range [][][]int64{{{0, 0}, {0, 0}}, {{1, 2, 3}}, {{2}, {4}}, {{0, 0, 0}, {1, 2, 3}}} {
		got, err := fixedMarginProbability(table, 1)
		if err != nil || got.P == nil || *got.P != 1 || !got.Exact {
			t.Fatal("fixed single table rejected", got, err)
		}
	}
	for _, table := range [][][]int64{nil, {{}}, {{1, 2}, {1}}, {{-1, 2}, {3, 4}}, {{4000001}}, {{2000001, 2000001}}} {
		if _, err := fixedMarginProbability(table, 1); err == nil {
			t.Fatal("invalid table accepted", table)
		}
	}
	tooMany := make([][]int64, 257)
	for i := range tooMany {
		tooMany[i] = []int64{1, 1}
	}
	if _, err := fixedMarginProbability(tooMany, 1); err == nil {
		t.Fatal("unbounded row count accepted")
	}
}

func TestBernoulliTailBoundFiniteSampleCoverage(t *testing.T) {
	const delta = .1
	for n := 1; n <= 30; n++ {
		for grid := 0; grid <= 20; grid++ {
			p := float64(grid) / 20
			miss := 0.0
			for hits := 0; hits <= n; hits++ {
				lo, hi := bernoulliTailBounds(hits, n, delta)
				q := float64(hits) / float64(n)
				if lo < 0 || lo > q || hi < q || hi > 1 {
					t.Fatal("invalid tail bound", hits, n, lo, hi)
				}
				if p >= lo && p <= hi {
					continue
				}
				ways := 1.0
				for j := 1; j <= hits; j++ {
					ways *= float64(n-j+1) / float64(j)
				}
				miss += ways * math.Pow(p, float64(hits)) * math.Pow(1-p, float64(n-hits))
			}
			if miss > delta+1e-12 {
				t.Fatalf("coverage failure n=%d p=%g miss=%g", n, p, miss)
			}
		}
	}
	lo, hi := bernoulliTailBounds(0, 1000, tableErrorProbability)
	want := -math.Expm1(-math.Log(2/tableErrorProbability) / 1000)
	if lo != 0 || math.Abs(hi-want) > 1e-15 {
		t.Fatal("zero-hit bound does not invert the exact KL expression", lo, hi, want)
	}
}
