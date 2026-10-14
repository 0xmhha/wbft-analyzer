package scenario

import "testing"

func TestCounterfactualDistributionsKeepSeedScope(t *testing.T) {
	runs := []SeedResult{{Seed: 1, Status: "complete", Heights: []Height{{Number: 1, Time: 100}, {Number: 2, Round: 1, Time: 102}}}, {Seed: 2, Status: "complete", Heights: []Height{{Number: 1, Time: 200}, {Number: 2, Round: 2, Time: 203}}}}
	ecdf, err := RoundECDF(runs)
	if err != nil || len(ecdf) != 3 || ecdf[0].Cumulative != 0.5 || ecdf[2].Cumulative != 1 {
		t.Fatalf("ecdf %+v %v", ecdf, err)
	}
	bands, err := TimeBands(runs)
	if err != nil || bands[1].Minimum != 2 || bands[1].Maximum != 3 || bands[1].Seeds != 2 {
		t.Fatalf("bands %+v %v", bands, err)
	}
	runs[1].Heights[1].Number = 3
	if _, err := TimeBands(runs); err == nil {
		t.Fatal("different seed range accepted")
	}
	if _, err := RoundECDF(runs); err == nil {
		t.Fatal("different seed scope pooled into ECDF")
	}
	runs[1].Status = "partial"
	if _, err := RoundECDF(runs); err == nil {
		t.Fatal("partial distribution marked complete")
	}
}

func TestHeaderPeriodDistributionUsesParentIntervals(t *testing.T) {
	runs := []SeedResult{{Seed: 1, Status: "complete", Heights: []Height{{Number: 1, Time: 101, PeriodSeconds: 1}, {Number: 2, Time: 104, PeriodSeconds: 3}}}, {Seed: 2, Status: "complete", Heights: []Height{{Number: 1, Time: 202, PeriodSeconds: 2}, {Number: 2, Time: 205, PeriodSeconds: 3}}}}
	got, err := PeriodECDF(runs)
	if err != nil || len(got) != 3 || got[2].Value != 3 || got[2].Count != 2 {
		t.Fatal("period distribution", err)
	}
	if runs[0].Heights[0].Round != 0 {
		t.Fatal("caller mutated")
	}
}
