package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type ObservationResult struct {
	DatasetID  int64  `json:"dataset_id"`
	NetworkID  int64  `json:"network_id"`
	Calls      int64  `json:"calls"`
	Skipped    bool   `json:"skipped"`
	Comparison string `json:"comparison"`
}

func Observations(ctx context.Context, s *store.Store, name, sourceKind, sha string, a observe.Archive) (res ObservationResult, err error) {
	if !logs.Identifier(name) {
		return res, errors.New("invalid observation dataset name")
	}
	snap, e := observe.Normalize(a)
	if e != nil {
		return res, e
	}
	meta, e := json.Marshal(map[string]any{"normalizer": observe.Normalizer, "from": snap.From, "to": snap.To, "source_kind": sourceKind, "source_sha256": sha})
	if e != nil {
		return res, e
	}
	node := snap.Node
	d, release, e := s.BeginObservations(ctx, store.NetworkKey{ChainID: node.ChainID.String(), GenesisHash: node.GenesisHash.String()}, name, meta)
	if e != nil {
		return res, e
	}
	defer release()
	res.DatasetID, res.NetworkID, res.Comparison = d.ID, d.NetworkID, snap.Comparison.Status
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		detail := ""
		if err != nil {
			detail = "observation import incomplete; see local diagnostics"
		}
		if e := s.FinishRange(cleanup, d.ID, res.Calls, detail); err == nil {
			err = e
		}
	}()
	if d.Status == "complete" {
		res.Skipped = true
		res.Calls = d.Progress
		return res, nil
	}
	if e = s.PutObservation(ctx, d.ID, sourceKind, sha, snap); e != nil {
		return res, e
	}
	res.Calls = int64(len(snap.Calls))
	return res, nil
}
