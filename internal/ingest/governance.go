package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type GovernanceResult struct {
	DatasetID int64  `json:"dataset_id"`
	NetworkID int64  `json:"network_id"`
	Calls     int64  `json:"calls"`
	Skipped   bool   `json:"skipped"`
	Snapshot  string `json:"snapshot"`
}

// Governance stores only normalized claims, never opaque source envelopes.
func Governance(ctx context.Context, s *store.Store, name, kind, sha string, archive governance.Archive) (res GovernanceResult, err error) {
	if !logs.Identifier(name) {
		return res, errors.New("invalid governance dataset name")
	}
	snap, err := governance.Normalize(archive)
	if err != nil {
		return res, err
	}
	info, err := store.GovernanceInfo(0, kind, sha, snap)
	if err != nil {
		return res, err
	}
	meta, err := json.Marshal(map[string]any{"normalizer": info.Normalizer, "snapshot": info.Snapshot, "source_kind": kind, "source_sha256": sha})
	if err != nil {
		return res, err
	}
	d, release, err := s.BeginGovernance(ctx, store.NetworkKey{ChainID: snap.Before.ChainID, GenesisHash: snap.Before.GenesisHash}, name, meta)
	if err != nil {
		return res, err
	}
	defer release()
	res.DatasetID, res.NetworkID, res.Snapshot = d.ID, d.NetworkID, info.Snapshot
	if d.Status == "complete" {
		res.Skipped, res.Calls = true, d.Progress
		return res, s.FinishRange(ctx, d.ID, d.Progress, "")
	}
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = s.FinishRange(cleanup, d.ID, 0, "governance import incomplete")
		}
	}()
	if _, err = s.PutGovernance(ctx, d.ID, kind, sha, archive); err != nil {
		return res, err
	}
	res.Calls = int64(len(snap.Calls))
	return res, nil
}
