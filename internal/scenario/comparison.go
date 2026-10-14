package scenario

import "errors"

const BaselineMethod = "wbft-round-baseline/1"

type RoundComparison struct {
	Method          string       `json:"method"`
	Status          string       `json:"status"`
	Alpha           float64      `json:"alpha"`
	P               *float64     `json:"p"`
	Recorded        Homogeneity  `json:"recorded_homogeneity"`
	Simulated       Homogeneity  `json:"simulated_homogeneity"`
	Permutation     *Permutation `json:"permutation"`
	RecordedCounts  []RoundCount `json:"recorded_counts"`
	SimulatedCounts []RoundCount `json:"simulated_counts"`
}

// CompareRounds applies the established run homogeneity gate before pooling.
// A single nonhomogeneous recorded run set cannot support a run permutation.
func CompareRounds(recorded, simulated []RoundCount, seed uint64) (RoundComparison, error) {
	out := RoundComparison{Method: BaselineMethod, Status: "unavailable", Alpha: 0.01, RecordedCounts: recorded, SimulatedCounts: simulated}
	var err error
	out.Recorded, err = RunHomogeneity(recorded)
	if err != nil {
		return out, err
	}
	out.Simulated, err = RunHomogeneity(simulated)
	if err != nil {
		return out, err
	}
	if len(simulated) < 2 {
		return out, errors.New("baseline comparison needs multiple simulation seeds")
	}
	if out.Recorded.P < out.Alpha || out.Simulated.P < out.Alpha {
		out.Method += "/run-permutation"
		if len(recorded) < 2 {
			out.Status = "insufficient_recorded_runs"
			return out, nil
		}
		p, err := RunPermutation(recorded, simulated, seed)
		if err != nil {
			return out, err
		}
		out.P = &p.P
		out.Permutation = &p
	} else {
		out.Method += "/fisher-two-sided"
		a, b, c, d := int64(0), int64(0), int64(0), int64(0)
		for _, r := range recorded {
			a += r.Late
			b += r.Total - r.Late
		}
		for _, r := range simulated {
			c += r.Late
			d += r.Total - r.Late
		}
		p, err := FisherTwoSided(a, b, c, d)
		if err != nil {
			return out, err
		}
		out.P = &p
	}
	out.Status = "distinguishable"
	if *out.P >= out.Alpha {
		out.Status = "not_distinguishable"
	}
	return out, nil
}
