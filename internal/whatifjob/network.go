package whatifjob

import (
	"context"
	"encoding/json"
	"os"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

// inspectNetwork reads verified retained objects rather than mutable metadata
// rows. The caller already holds the entire dataset's read lease.
func inspectNetwork(ctx context.Context, s *store.Store, dataset store.Dataset, network store.NetworkKey, inputs []store.MessageInput, primary messages.Prepared, evidence *whatif.Evidence) ([]whatif.NetworkBinding, whatif.NetworkScope, error) {
	scope := whatif.NetworkScope{Status: "complete", Clock: "unknown", Inputs: []whatif.NetworkInput{}}
	var metadata struct {
		Clock messages.Clock `json:"clock"`
	}
	if json.Unmarshal(dataset.Metadata, &metadata) == nil && metadata.Clock.Model != "" {
		scope.Clock = metadata.Clock.Model
		scope.SkewMS = metadata.Clock.SkewMS
	}
	if dataset.Status != "complete" {
		scope.Status = "incomplete_dataset"
	}
	all := []messages.Record{}
	for _, input := range inputs {
		info := whatif.NetworkInput{Input: input.Summary.ID, Kind: input.Summary.Kind, Node: input.Summary.Node, SHA256: input.Summary.SHA256, Status: "verified"}
		prepared := primary
		cleanup := func() {}
		if input.Summary.ID != primary.Summary.ID {
			refs, err := s.InputFiles(ctx, dataset.ID, input.Summary.ID)
			if err != nil {
				return nil, scope, err
			}
			var directory string
			switch input.Summary.Kind {
			case "journal":
				directory, err = reexec.Snapshot(ctx, input.Summary, refs)
			case "frames":
				directory, err = reexec.SnapshotFrames(ctx, input.Summary, refs)
			default:
				info.Status = "unsupported_input"
			}
			if err != nil {
				info.Status = "snapshot_unavailable"
			}
			if directory != "" {
				prepared = messages.Prepared{Input: messages.Input{ID: input.Summary.ID, Kind: input.Summary.Kind, Node: input.Summary.Node, Path: directory}, Summary: input.Summary}
				cleanup = func() { _ = os.RemoveAll(directory) }
			}
		}
		if info.Status == "verified" {
			part := []messages.Record{}
			stats, err := messages.Read(ctx, prepared, network.ChainID, network.GenesisHash, func(record messages.Record) error {
				if len(part)+len(all) >= 1000000 {
					return whatif.ErrEvidence
				}
				part = append(part, record)
				return ctx.Err()
			})
			if err != nil {
				info.Status = "reader_refused"
			} else if stats.GapRecords > 0 || stats.SequenceGaps > 0 || stats.PartialRuns > 0 {
				info.Status = "source_gaps"
			} else {
				all = append(all, part...)
			}
		}
		cleanup()
		if info.Status != "verified" {
			scope.Status = "source_unavailable"
		}
		scope.Inputs = append(scope.Inputs, info)
	}
	scope.Seal()
	if scope.Status != "complete" {
		return []whatif.NetworkBinding{}, scope, nil
	}
	bindings, err := evidence.BindNetwork(primary.Summary.ID, primary.Summary.Node, all, messages.Clock{Model: scope.Clock, SkewMS: scope.SkewMS})
	return bindings, scope, err
}
