package scenario

import (
	"context"
	"errors"
	"strings"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

type MessageInput struct {
	Source  Input             `json:"source"`
	Stats   messages.Stats    `json:"stats"`
	Records []messages.Record `json:"-"`
}

// InspectMessageSnapshot reads a reconstructed immutable snapshot, retaining
// source coordinates for each projection. The caller holds the dataset lease.
func InspectMessageSnapshot(ctx context.Context, p messages.Prepared, chain, genesis string) (MessageInput, error) {
	out := MessageInput{Source: Input{ID: p.Summary.ID, Kind: p.Summary.Kind, Node: p.Summary.Node, SHA256: p.Summary.SHA256}, Records: []messages.Record{}}
	if p.Input.ID != p.Summary.ID || p.Input.Kind != p.Summary.Kind || !strings.EqualFold(p.Input.Node, p.Summary.Node) || !hexLength(p.Summary.SHA256, 64) {
		return out, errors.New("scenario message identity mismatch")
	}
	actual, err := messages.Fingerprint(ctx, p.Input)
	if err != nil || actual.SHA256 != p.Summary.SHA256 {
		return out, errors.New("scenario message fingerprint mismatch")
	}
	stats, err := messages.Read(ctx, p, chain, genesis, func(r messages.Record) error {
		if len(out.Records) >= 1000000 {
			return errors.New("scenario message count exceeds bound")
		}
		out.Records = append(out.Records, r)
		return nil
	})
	out.Stats = stats
	if err != nil {
		return out, err
	}
	if stats.GapRecords > 0 || stats.SequenceGaps > 0 || stats.PartialRuns > 0 {
		return out, errors.New("scenario message recording incomplete")
	}
	after, err := messages.Fingerprint(ctx, p.Input)
	if err != nil || after.SHA256 != actual.SHA256 {
		return out, errors.New("scenario snapshot changed while reading")
	}
	return out, nil
}

// PairMessageInputs pairs the complete selected snapshot scope. Clock
// declarations are retained; timestamps never make an ambiguous copy unique.
func PairMessageInputs(inputs []MessageInput, clock pairs.Clock) ([]pairs.Pair, error) {
	if len(inputs) == 0 || len(inputs) > 256 {
		return nil, errors.New("invalid message snapshot scope")
	}
	records := []messages.Record{}
	seen := map[string]bool{}
	for _, in := range inputs {
		if seen[in.Source.ID] || !hexLength(in.Source.SHA256, 64) || in.Stats.GapRecords > 0 || in.Stats.SequenceGaps > 0 || in.Stats.PartialRuns > 0 {
			return nil, errors.New("unproved message snapshot")
		}
		seen[in.Source.ID] = true
		if len(records)+len(in.Records) > 1000000 {
			return nil, errors.New("message scope exceeds bound")
		}
		for _, r := range in.Records {
			if r.Input != in.Source.ID || r.Node != in.Source.Node {
				return nil, errors.New("message snapshot source mismatch")
			}
		}
		records = append(records, in.Records...)
	}
	projected := pairs.ProjectRecords(records)
	return pairs.PairEndpoints(projected.Endpoints, clock), nil
}
