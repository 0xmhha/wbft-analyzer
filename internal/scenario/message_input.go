package scenario

import (
	"context"
	"errors"
	"sort"
	"strings"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

type MessageInput struct {
	Source  Input             `json:"source"`
	Stats   messages.Stats    `json:"stats"`
	Records []messages.Record `json:"-"`
}

// selectTransportInputs makes alternate observations an explicit model choice.
// The empty selection preserves the full candidate scope, including records
// without measured clocks. Explicit selection allows one source per node;
// unselected snapshots still belong to fitting provenance and configuration.
func selectTransportInputs(inputs []MessageInput, ids []string, nodes []string) ([]MessageInput, error) {
	if len(ids) > 256 {
		return nil, errors.New("transport selection exceeds bound")
	}
	byID := map[string]MessageInput{}
	for _, input := range inputs {
		if _, exists := byID[input.Source.ID]; exists || input.Source.ID == "" {
			return nil, errors.New("duplicate message source identity")
		}
		byID[input.Source.ID] = input
	}
	out := append([]MessageInput(nil), inputs...)
	if len(ids) > 0 {
		out = []MessageInput{}
		seenIDs, seenNodes := map[string]bool{}, map[string]bool{}
		knownNodes := map[string]bool{}
		for _, node := range nodes {
			knownNodes[strings.ToLower(node)] = true
		}
		for _, id := range ids {
			input, exists := byID[id]
			node := strings.ToLower(input.Source.Node)
			if !exists || seenIDs[id] || seenNodes[node] || !knownNodes[node] || input.Source.Kind != "journal" && input.Source.Kind != "frames" {
				return nil, errors.New("invalid transport source selection")
			}
			seenIDs[id], seenNodes[node] = true, true
			out = append(out, input)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source.ID < out[j].Source.ID })
	return out, nil
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
	return PairMessageInputsMetric(inputs, clock, "link")
}

func PairMessageInputsMetric(inputs []MessageInput, clock pairs.Clock, metric string) ([]pairs.Pair, error) {
	if !ValidWireMetric(metric) {
		return nil, errors.New("unsupported wire measurement")
	}
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
	if metric == pairs.WriteStartToReadComplete {
		projected = pairs.ProjectIORecords(records)
	}
	return pairs.PairEndpoints(projected.Endpoints, clock), nil
}
