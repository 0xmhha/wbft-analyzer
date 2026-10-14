package scenario

import (
	"errors"
	"math"
)

type RoundCount struct {
	Late  int64 `json:"late"`
	Total int64 `json:"total"`
}

type Homogeneity struct {
	Statistic  float64  `json:"statistic"`
	DF         int      `json:"degrees_of_freedom"`
	P          float64  `json:"p"`
	Dispersion *float64 `json:"dispersion"`
}

// RunHomogeneity follows the baseline's binomial chi-square comparison.
func RunHomogeneity(runs []RoundCount) (Homogeneity, error) {
	if len(runs) == 0 || len(runs) > 4096 {
		return Homogeneity{}, errors.New("invalid run count")
	}
	late, total := int64(0), int64(0)
	for _, r := range runs {
		if r.Total <= 0 || r.Total > 1000000 || r.Late < 0 || r.Late > r.Total {
			return Homogeneity{}, errors.New("invalid round counts")
		}
		late += r.Late
		total += r.Total
	}
	out := Homogeneity{DF: len(runs) - 1, P: 1}
	if out.DF == 0 || late == 0 || late == total {
		return out, nil
	}
	p := float64(late) / float64(total)
	for _, r := range runs {
		delta := float64(r.Late) - float64(r.Total)*p
		out.Statistic += delta * delta / (float64(r.Total) * p * (1 - p))
	}
	out.P = gammaQ(float64(out.DF)/2, out.Statistic/2)
	dispersion := out.Statistic / float64(out.DF)
	out.Dispersion = &dispersion
	return out, nil
}

func gammaQ(a, z float64) float64 {
	if z <= 0 {
		return 1
	}
	lg, _ := math.Lgamma(a)
	if z < a+1 {
		term, total, n := 1/a, 1/a, a
		for range 10000 {
			n++
			term *= z / n
			total += term
			if math.Abs(term) < math.Abs(total)*1e-15 {
				break
			}
		}
		return max(0, 1-total*math.Exp(-z+a*math.Log(z)-lg))
	}
	const tiny = 1e-300
	b := z + 1 - a
	c := 1 / tiny
	d := 1 / b
	h := d
	for i := 1; i < 10000; i++ {
		an := -float64(i) * (float64(i) - a)
		b += 2
		d = an*d + b
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = b + an/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		delta := d * c
		h *= delta
		if math.Abs(delta-1) < 1e-15 {
			break
		}
	}
	return min(1, h*math.Exp(-z+a*math.Log(z)-lg))
}
