package observe

import (
	"errors"
	"math/big"
	"slices"
	"strings"

	"github.com/0xmhha/wbft/observe/participation"
)

const maxRoundChangeRows = 65536

// RoundChangeComparison compares independent RPC claims with the captured
// participation records. Unknown counts remain absent rather than becoming zero.
// Original rows remain in their request data, without duplicating large arrays
// in capture listings. A difference is not a consensus or clock verdict.
type RoundChangeComparison struct {
	Status          string   `json:"status"`
	ComputedCount   *int     `json:"computed_count,omitempty"`
	ReportedCount   *int     `json:"reported_count,omitempty"`
	DifferentRows   *int     `json:"different_rows,omitempty"`
	DifferentFields []string `json:"different_fields"`
}

func validateRoundChanges(rows []participation.RoundChange, from, to *big.Int) error {
	if len(rows) > maxRoundChangeRows {
		return errors.New("round-change claims exceed metadata bounds; narrow the range")
	}
	seen := map[[2]string]bool{}
	for _, row := range rows {
		h, ok := number(row.Height)
		_, roundOK := number(row.Round)
		nextOK := true
		if row.Next != "" {
			_, nextOK = number(row.Next)
		}
		key := [2]string{row.Height, row.Round}
		if !ok || h.Cmp(from) < 0 || h.Cmp(to) > 0 || !roundOK || !nextOK || !address(row.Proposer) || !oneOf(row.Cause, "", "timeout", "f_plus_one", "finalize_fail", "catch_up") || seen[key] {
			return errors.New("invalid or duplicate round-change claim")
		}
		seen[key] = true
	}
	return nil
}

func compareRoundChanges(records []participation.Record, haveRecords bool, reported []participation.RoundChange, haveReported bool) (*RoundChangeComparison, error) {
	out := &RoundChangeComparison{Status: "unavailable", DifferentFields: []string{}}
	var computed []participation.RoundChange
	if haveRecords {
		computed = participation.RoundChanges(records)
		if len(computed) > maxRoundChangeRows {
			return nil, errors.New("computed round changes exceed metadata bounds; narrow the range")
		}
		n := len(computed)
		out.ComputedCount = &n
	}
	if haveReported {
		n := len(reported)
		out.ReportedCount = &n
	}
	if !haveRecords || !haveReported {
		return out, nil
	}
	fields := map[string]bool{}
	different := max(len(computed), len(reported)) - min(len(computed), len(reported))
	if len(computed) != len(reported) {
		fields["count"] = true
	}
	for i := 0; i < min(len(computed), len(reported)); i++ {
		a, b := computed[i], reported[i]
		changed := false
		for _, field := range []struct {
			name string
			same bool
		}{{"height", a.Height == b.Height}, {"round", a.Round == b.Round}, {"proposer", strings.EqualFold(a.Proposer, b.Proposer)}, {"cause", a.Cause == b.Cause}, {"next", a.Next == b.Next}} {
			if !field.same {
				fields[field.name] = true
				changed = true
			}
		}
		if changed {
			different++
		}
	}
	out.DifferentRows = &different
	for field := range fields {
		out.DifferentFields = append(out.DifferentFields, field)
	}
	slices.Sort(out.DifferentFields)
	out.Status = "match"
	if different > 0 {
		out.Status = "different"
	}
	return out, nil
}
