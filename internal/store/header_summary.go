package store

import (
	"context"
	"sort"
	"strconv"
)

type ValidatorSummary struct {
	Address       string   `json:"address"`
	Eligible      int64    `json:"eligible"`
	Known         int64    `json:"known"`
	Unknown       int64    `json:"unknown"`
	Prepared      int64    `json:"prepared"`
	Committed     int64    `json:"committed"`
	InclusionRate *float64 `json:"inclusion_rate"`
	RoundZero     int64    `json:"round_zero"`
	Proposed      int64    `json:"proposed"`
	Missed        int64    `json:"missed"`
}
type RoundCount struct {
	Round int64 `json:"round"`
	Count int64 `json:"count"`
}
type HeaderSummary struct {
	Heights        int64              `json:"heights"`
	UnknownRound   int64              `json:"unknown_round"`
	MissingHeights int64              `json:"missing_heights"`
	Validators     []ValidatorSummary `json:"validators"`
	Rounds         []RoundCount       `json:"rounds"`
}

// HeaderSummary streams windows and counts eligibility across changing sets.
// The rate is unavailable if any eligible height has no immutable child proof.
func (s *Store) HeaderSummary(ctx context.Context, nid int64, from, to uint64) (HeaderSummary, error) {
	out := HeaderSummary{Validators: []ValidatorSummary{}, Rounds: []RoundCount{}}
	counts := map[string]*ValidatorSummary{}
	rounds := map[int64]int64{}
	get := func(a string) *ValidatorSummary {
		if counts[a] == nil {
			counts[a] = &ValidatorSummary{Address: a}
		}
		return counts[a]
	}
	for a := from; ; {
		b := a + 1023
		if b < a || b > to {
			b = to
		}
		rows, err := s.HeaderRows(ctx, nid, strconv.FormatUint(a, 10), strconv.FormatUint(b, 10), nil, "")
		if err != nil {
			return out, err
		}
		for _, r := range rows {
			out.Heights++
			if r.Fact.Number == "0" {
				continue
			}
			get(r.Fact.RoundZero).RoundZero++
			get(r.Fact.Coinbase).Proposed++
			for _, o := range r.Missed {
				get(o.Address).Missed += o.Count
			}
			if r.DecisionRound == nil {
				out.UnknownRound++
			} else {
				rounds[*r.DecisionRound]++
			}
			for _, c := range r.Cells {
				x := get(c.Address)
				x.Eligible++
				if c.Committed == nil {
					x.Unknown++
				} else {
					x.Known++
					if *c.Committed {
						x.Committed++
					}
					if *c.Prepared {
						x.Prepared++
					}
				}
			}
		}
		if b == to {
			break
		}
		a = b + 1
	}
	out.MissingHeights = int64(to-from+1) - out.Heights
	for _, v := range counts {
		if v.Eligible > 0 && v.Unknown == 0 && out.MissingHeights == 0 {
			rate := float64(v.Committed) / float64(v.Eligible)
			v.InclusionRate = &rate
		}
		out.Validators = append(out.Validators, *v)
	}
	for r, n := range rounds {
		out.Rounds = append(out.Rounds, RoundCount{r, n})
	}
	sort.Slice(out.Validators, func(i, j int) bool { return out.Validators[i].Address < out.Validators[j].Address })
	sort.Slice(out.Rounds, func(i, j int) bool { return out.Rounds[i].Round < out.Rounds[j].Round })
	return out, nil
}
