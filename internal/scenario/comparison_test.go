package scenario

import "testing"

func TestComparisonSelectsEstablishedMethod(t *testing.T) {
	same := []RoundCount{{15, 100}, {15, 100}, {15, 100}}
	c, err := CompareRounds(same, same, 1)
	if err != nil || c.Status != "not_distinguishable" || c.Permutation != nil {
		t.Fatalf("same %+v/%v", c, err)
	}
	different := []RoundCount{{80, 100}, {80, 100}, {80, 100}}
	c, err = CompareRounds(same, different, 1)
	if err != nil || c.Status != "distinguishable" {
		t.Fatalf("different %+v/%v", c, err)
	}
	varied := []RoundCount{{0, 100}, {100, 100}}
	c, err = CompareRounds(varied, varied, 1)
	if err != nil || c.Permutation == nil || c.Status != "not_distinguishable" {
		t.Fatalf("varied %+v/%v", c, err)
	}
	c, err = CompareRounds(same[:1], varied, 1)
	if err != nil || c.P != nil || c.Status != "insufficient_recorded_runs" {
		t.Fatalf("insufficient %+v/%v", c, err)
	}
}
