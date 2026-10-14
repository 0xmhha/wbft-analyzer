package scenario

import (
	"errors"
	"math/big"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

// ScopeCounts records exclusions from the fit, never deletions from its inputs.
type ScopeCounts struct {
	AppExcluded   int64 `json:"application_excluded"`
	AppUnscoped   int64 `json:"application_unscoped"`
	LinksExcluded int64 `json:"links_excluded"`
	LinksUnscoped int64 `json:"links_unscoped"`
}

func heightScope(height string, from, to uint64) (inside, known bool) {
	if height == "" || len(height) > 1 && height[0] == '0' {
		return false, false
	}
	for _, ch := range height {
		if ch < '0' || ch > '9' {
			return false, false
		}
	}
	n, ok := new(big.Int).SetString(height, 10)
	if !ok {
		return false, false
	}
	return n.Cmp(new(big.Int).SetUint64(from)) >= 0 && n.Cmp(new(big.Int).SetUint64(to)) <= 0, true
}

// ScopeApplication preserves unknown heights for the timing validator.
// A pending request outside the selected height range is not a failed sample
// within it. Runtime events remain available to the independent lifecycle fit.
func ScopeApplication(xs []logs.Event, from, to uint64) ([]logs.Event, ScopeCounts, error) {
	counts := ScopeCounts{}
	if from < 1 || to < from {
		return nil, counts, errors.New("invalid application fitting range")
	}
	out := []logs.Event{}
	for _, x := range xs {
		var height string
		switch x.Record.Kind {
		case event.BuildRequest:
			if x.Record.View != nil {
				height = x.Record.View.Seq
			}
		case event.ProposalSubmitted, event.CommitResult, event.BuildHandover, event.BuildStarted, event.BuildFinished:
			height, _ = x.Record.Fields["number"].(string)
		default:
			continue
		}
		inside, known := heightScope(height, from, to)
		if known && !inside {
			counts.AppExcluded++
			continue
		}
		if !known {
			counts.AppUnscoped++
		}
		out = append(out, x)
	}
	return out, counts, nil
}

// ScopeLinks runs after whole-input pairing. All candidate views must prove
// exclusion; filtering endpoints first must not manufacture a unique pair.
func ScopeLinks(xs []pairs.Pair, from, to uint64) ([]pairs.Pair, ScopeCounts, error) {
	counts := ScopeCounts{}
	if from < 1 || to < from {
		return nil, counts, errors.New("invalid link fitting range")
	}
	out := []pairs.Pair{}
	for _, p := range xs {
		if p.Strength != "link" {
			continue
		}
		heights := []string{}
		if p.Height != "" {
			heights = append(heights, p.Height)
		}
		for _, view := range p.Views {
			heights = append(heights, view.Height)
		}
		unknown, inside := len(heights) == 0, false
		for _, height := range heights {
			included, known := heightScope(height, from, to)
			inside = inside || included
			unknown = unknown || !known
		}
		if !inside && !unknown {
			counts.LinksExcluded++
			continue
		}
		if unknown {
			counts.LinksUnscoped++
		}
		out = append(out, p)
	}
	return out, counts, nil
}
