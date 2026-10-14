package scenario

import "testing"

func TestPermutationIndependentRuns(t *testing.T) {
	a := []RoundCount{{0, 10}, {0, 10}}
	b := []RoundCount{{10, 10}, {10, 10}}
	got, err := RunPermutation(a, b, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Exact || got.Splits != 6 || got.P != 1.0/3 {
		t.Fatalf("exact %+v", got)
	}
	a = make([]RoundCount, 32)
	b = make([]RoundCount, 32)
	for i := range a {
		a[i] = RoundCount{0, 10}
		b[i] = RoundCount{10, 10}
	}
	got, err = RunPermutation(a, b, 17)
	if err != nil {
		t.Fatal(err)
	}
	again, err := RunPermutation(a, b, 17)
	if err != nil || got != again || got.Exact || got.Splits != 200000 || got.P >= 0.01 {
		t.Fatalf("sample %+v/%+v %v", got, again, err)
	}
	if _, err := RunPermutation(a, nil, 1); err == nil {
		t.Fatal("missing runs accepted")
	}
}
