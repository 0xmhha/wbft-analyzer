package scenario

import (
	"errors"
	"math"
	"math/big"
	"math/bits"
	"math/rand/v2"
	"sort"
)

const (
	tableExactLimit             = 200000
	tableSampleLimit            = 200000
	tableWorkLimit        int64 = 200000000
	tableErrorProbability       = 1e-6
)

// ConditionalProbability compares all cells with fixed row and column totals.
// Sampling bounds describe the underlying conditional tail probability; P is
// the plus-one Monte Carlo p-value. Exact underflow retains the log probability.
type ConditionalProbability struct {
	Method           string   `json:"method"`
	P                *float64 `json:"p"`
	LogP             *float64 `json:"log_p,omitempty"`
	Exact            bool     `json:"exact"`
	Underflow        bool     `json:"underflow"`
	Samples          int      `json:"samples"`
	Seed             uint64   `json:"seed,string"`
	Lower            float64  `json:"lower"`
	Upper            float64  `json:"upper"`
	ErrorProbability float64  `json:"error_probability"`
	Issue            string   `json:"issue,omitempty"`
	LogMassTolerance float64  `json:"log_mass_tolerance"`
}

type conditionalTable struct {
	cells                         [][]int64
	rows, columns                 []int64
	total                         int64
	logFactorial                  []float64
	observed, tolerance, constant float64
	observedCells                 []int64
	integerWork                   int64
	ambiguous                     bool
}

func prepareConditionalTable(input [][]int64) (conditionalTable, error) {
	var t conditionalTable
	if len(input) == 0 || len(input) > 256 || len(input[0]) == 0 || len(input[0]) > 2048 || len(input)*len(input[0]) > 65536 {
		return t, errors.New("contingency table exceeds bounded dimensions")
	}
	columns := make([]int64, len(input[0]))
	for _, row := range input {
		if len(row) != len(columns) {
			return t, errors.New("ragged contingency table")
		}
		for j, n := range row {
			if n < 0 || n > 4000000 || t.total > 4000000-n {
				return t, errors.New("invalid contingency count")
			}
			t.total += n
			columns[j] += n
		}
	}
	for _, row := range input {
		var sum int64
		x := []int64{}
		for j, n := range row {
			if columns[j] > 0 {
				x = append(x, n)
				sum += n
			}
		}
		if sum > 0 {
			t.cells = append(t.cells, x)
		}
	}
	// Small rows first leave the largest row determined by the remaining
	// margins. Caller rows and their ordering remain untouched.
	sort.Slice(t.cells, func(i, j int) bool {
		a, b := int64(0), int64(0)
		for _, n := range t.cells[i] {
			a += n
		}
		for _, n := range t.cells[j] {
			b += n
		}
		if a != b {
			return a < b
		}
		for k, n := range t.cells[i] {
			if n != t.cells[j][k] {
				return n < t.cells[j][k]
			}
		}
		return false
	})
	for _, n := range columns {
		if n > 0 {
			t.columns = append(t.columns, n)
		}
	}
	for _, row := range t.cells {
		var n int64
		for _, x := range row {
			n += x
		}
		t.rows = append(t.rows, n)
	}
	t.logFactorial = make([]float64, t.total+1)
	sum, correction := 0.0, 0.0
	for i := 1; i < len(t.logFactorial); i++ {
		y := math.Log(float64(i)) - correction
		next := sum + y
		correction = (next - sum) - y
		sum = next
		t.logFactorial[i] = sum
	}
	for _, row := range t.cells {
		t.observedCells = append(t.observedCells, row...)
	}
	sort.Slice(t.observedCells, func(i, j int) bool { return t.observedCells[i] < t.observedCells[j] })
	t.observed = t.score(t.cells)
	t.tolerance = math.Max(1e-9, 64*(math.Nextafter(t.observed, math.Inf(1))-t.observed))
	for _, n := range t.rows {
		t.constant += t.logFactorial[n]
	}
	for _, n := range t.columns {
		t.constant += t.logFactorial[n]
	}
	t.constant -= t.logFactorial[t.total]
	return t, nil
}

func (t conditionalTable) score(cells [][]int64) float64 {
	sum, correction := 0.0, 0.0
	for _, row := range cells {
		for _, n := range row {
			y := t.logFactorial[n] - correction
			next := sum + y
			correction = (next - sum) - y
			sum = next
		}
	}
	return sum
}

// Near a floating-point tie, compare factorial ratios as integers. An
// unresolved bounded comparison makes the whole test unavailable rather than
// assigning an ambiguous table to either tail.
func (t *conditionalTable) extreme(cells [][]int64, score float64) (bool, bool) {
	if math.Abs(score-t.observed) > t.tolerance {
		return score > t.observed, true
	}
	values := make([]int64, 0, len(t.observedCells))
	for _, row := range cells {
		values = append(values, row...)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	var work int64
	for i, n := range values {
		a := t.observedCells[i]
		if n <= 1 && a <= 1 {
			continue
		}
		if n > a {
			work += n - a
		} else {
			work += a - n
		}
	}
	if work > 100000 || t.integerWork > 5000000-work {
		t.ambiguous = true
		return false, false
	}
	t.integerWork += work
	var numerator, denominator, factor big.Int
	numerator.SetInt64(1)
	denominator.SetInt64(1)
	for i, n := range values {
		a := t.observedCells[i]
		if n > a {
			factor.MulRange(a+1, n)
			numerator.Mul(&numerator, &factor)
		} else if n < a {
			factor.MulRange(n+1, a)
			denominator.Mul(&denominator, &factor)
		}
	}
	return numerator.Cmp(&denominator) >= 0, true
}

// fixedMarginProbability uses the probability-mass definition for any table
// shape. A bounded incomplete enumeration is discarded before sampling.
func fixedMarginProbability(input [][]int64, seed uint64) (ConditionalProbability, error) {
	t, err := prepareConditionalTable(input)
	if err != nil {
		return ConditionalProbability{}, err
	}
	out := ConditionalProbability{Method: "fixed_margins_probability_mass/exact", Exact: true, Seed: seed, LogMassTolerance: t.tolerance}
	if len(t.rows) < 2 || len(t.columns) < 2 {
		p, logp := 1.0, 0.0
		out.P = &p
		out.LogP = &logp
		out.Lower = 1
		out.Upper = 1
		out.Samples = 1
		return out, nil
	}
	cells := make([][]int64, len(t.rows))
	for i := range cells {
		cells[i] = make([]int64, len(t.columns))
	}
	remaining := append([]int64(nil), t.columns...)
	visits := 0
	logSum := math.Inf(-1)
	var visit func(int, int, int64) bool
	visit = func(row, column int, left int64) bool {
		visits++
		if visits > tableExactLimit {
			return false
		}
		if row == len(t.rows)-1 {
			copy(cells[row], remaining)
			out.Samples++
			score := t.score(cells)
			extreme, known := t.extreme(cells, score)
			if !known {
				return false
			}
			if extreme {
				logp := t.constant - score
				if math.IsInf(logSum, -1) {
					logSum = logp
				} else {
					hi, lo := math.Max(logSum, logp), math.Min(logSum, logp)
					logSum = hi + math.Log1p(math.Exp(lo-hi))
				}
			}
			return true
		}
		if column == len(t.columns)-1 {
			if left < 0 || left > remaining[column] {
				return true
			}
			cells[row][column] = left
			remaining[column] -= left
			complete := visit(row+1, 0, t.rows[row+1])
			remaining[column] += left
			return complete
		}
		var capacity int64
		for _, n := range remaining[column+1:] {
			capacity += n
		}
		lo, hi := max(int64(0), left-capacity), min(left, remaining[column])
		for n := lo; n <= hi; n++ {
			cells[row][column] = n
			remaining[column] -= n
			complete := visit(row, column+1, left-n)
			remaining[column] += n
			if !complete {
				return false
			}
		}
		return true
	}
	if len(t.rows)*len(t.columns) <= 256 && visit(0, 0, t.rows[0]) {
		logSum = math.Min(0, logSum)
		p := math.Exp(logSum)
		out.P = &p
		out.LogP = &logSum
		out.Lower = p
		out.Upper = p
		if p == 0 {
			out.Underflow = true
			out.Upper = math.SmallestNonzeroFloat64
		}
		return out, nil
	}
	if t.ambiguous {
		return ConditionalProbability{Method: "fixed_margins_probability_mass/unavailable", Seed: seed, Upper: 1, Issue: "conditional_mass_precision_limit", LogMassTolerance: t.tolerance}, nil
	}
	t.integerWork = 0
	out = ConditionalProbability{Method: "fixed_margins_probability_mass/monte_carlo", Seed: seed, Upper: 1, ErrorProbability: tableErrorProbability, LogMassTolerance: t.tolerance}
	work := (t.total-t.rows[len(t.rows)-1]+int64(len(t.columns)))*int64(bits.Len(uint(len(t.columns)))+1) + int64(len(t.rows)*len(t.columns))
	trials := int(min(int64(tableSampleLimit), tableWorkLimit/work))
	if trials == 0 {
		out.Issue = "conditional_sampling_work_limit"
		return out, nil
	}
	rng := rand.New(rand.NewPCG(seed, 0x74696d652d746162))
	tree := make([]int64, len(t.columns)+1)
	add := func(index int, n int64) {
		for i := index + 1; i < len(tree); i += i & -i {
			tree[i] += n
		}
	}
	hits := 0
	for range trials {
		clear(tree)
		copy(remaining, t.columns)
		for _, row := range cells {
			clear(row)
		}
		for i, n := range remaining {
			add(i, n)
		}
		left := t.total
		for i, count := range t.rows[:len(t.rows)-1] {
			for range count {
				rank := rng.Int64N(left)
				index := 0
				for bit := 1 << (bits.Len(uint(len(t.columns))) - 1); bit > 0; bit >>= 1 {
					next := index + bit
					if next < len(tree) && tree[next] <= rank {
						rank -= tree[next]
						index = next
					}
				}
				cells[i][index]++
				remaining[index]--
				add(index, -1)
				left--
			}
		}
		copy(cells[len(cells)-1], remaining)
		extreme, known := t.extreme(cells, t.score(cells))
		if !known {
			out.Issue = "conditional_mass_precision_limit"
			return out, nil
		}
		if extreme {
			hits++
		}
	}
	p := float64(hits+1) / float64(trials+1)
	out.P = &p
	out.Samples = trials
	out.Lower, out.Upper = bernoulliTailBounds(hits, trials, tableErrorProbability)
	return out, nil
}

// Inverting the fixed-sample Bernoulli Chernoff bound gives a two-sided
// confidence set for the conditional tail probability. There is no adaptive
// stopping based on sampled hits, and no normal approximation for rare tails.
func bernoulliTailBounds(hits, trials int, errorProbability float64) (float64, float64) {
	q := float64(hits) / float64(trials)
	target := math.Log(2/errorProbability) / float64(trials)
	kl := func(p float64) float64 {
		if q == 0 {
			return -math.Log1p(-p)
		}
		if q == 1 {
			return -math.Log(p)
		}
		return q*(math.Log(q)-math.Log(p)) + (1-q)*(math.Log1p(-q)-math.Log1p(-p))
	}
	a, b := 0.0, q
	for range 64 {
		mid := (a + b) / 2
		if kl(mid) > target {
			a = mid
		} else {
			b = mid
		}
	}
	lower := a
	a, b = q, 1
	for range 64 {
		mid := (a + b) / 2
		if kl(mid) > target {
			b = mid
		} else {
			a = mid
		}
	}
	return lower, b
}
