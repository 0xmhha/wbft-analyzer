package baseline

import (
	"math"
	"testing"
)

func TestIndependentRunsHaveEqualWeightAndMissingIsNotZero(t *testing.T) {
	runs := []Run{{Dataset: 1, Observers: []Observer{{Node: "n", Profile: "p", Known: 100, Bins: []Bin{{"0", 90}, {"1", 10}}}}}, {Dataset: 2, Observers: []Observer{{Node: "n", Profile: "p", Known: 10, Bins: []Bin{{"0", 0}, {"1", 10}}}}}, {Dataset: 3, Observers: []Observer{{Node: "n", Profile: "p", Known: 0, Unknown: 2, Missing: 98, Bins: []Bin{}}}}}
	cs := Compare(runs)
	for _, c := range cs {
		if c.Round == "1" {
			if c.Runs != 2 || c.Mean == nil || math.Abs(*c.Mean-.55) > 1e-12 || c.Variance == nil || math.Abs(*c.Variance-.405) > 1e-12 || c.Samples[2].Fraction != nil {
				t.Fatal(c)
			}
		}
	}
	if cs := Compare(runs[:1]); cs[0].Variance != nil {
		t.Fatal("one run fabricated variance", cs)
	}
}
