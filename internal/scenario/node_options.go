package scenario

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// InspectNodeOptions reads an already verified immutable journal directory.
// Changed options across segments require an explicit time-varying model.
func InspectNodeOptions(ctx context.Context, directory string, address types.Address) (Node, *types.Config, error) {
	out := Node{Address: address}
	reader, err := journal.OpenReader(nil, directory)
	if err != nil {
		return out, nil, err
	}
	var first []byte
	var config *types.Config
	records := 0
	for {
		if err := ctx.Err(); err != nil {
			return out, nil, err
		}
		rec, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, nil, err
		}
		records++
		if records > 1000000 {
			return out, nil, errors.New("node configuration scan exceeds bound")
		}
		segment, ok := rec.Body.(*journal.SegmentRec)
		if !ok {
			continue
		}
		if segment.Self != address || segment.Core.Self != address || segment.Core.BacklogLimit > math.MaxInt32 || segment.Core.Profile != "" && segment.Core.Profile != "compat" && segment.Core.Profile != "improved" {
			return out, nil, errors.New("invalid recorded node configuration")
		}
		raw, err := json.Marshal(segment.Core)
		if err != nil {
			return out, nil, err
		}
		if first != nil && string(raw) != string(first) {
			return out, nil, errors.New("recorded node options change across segments")
		}
		if first == nil {
			first = raw
			config, err = segment.Core.Configuration()
			if err != nil {
				return out, nil, err
			}
			out.Improvements = segment.Core.Improvements
			out.BacklogLimit = int(segment.Core.BacklogLimit)
			out.Profile = segment.Core.Profile
			out.ProfileEvidence = "recorded"
			if out.Profile == "" {
				if segment.Core.Improvements != uint64(consensus.RestartSafety) {
					return out, nil, errors.New("recorded behavior profile unavailable")
				}
				// The name is derived only for simulator metadata; the exact recorded
				// flags determine behavior and remain authoritative.
				out.Profile = "compat"
				out.ProfileEvidence = "derived_restart_safety_flags"
			}
		}
	}
	if first == nil {
		return out, nil, errors.New("recorded node options unavailable")
	}
	// WAL replay and sign floor are not proved by CoreOptions. Caller must bind
	// the NODE_START/runtime configuration before declaring a complete model.
	return out, config, nil
}
