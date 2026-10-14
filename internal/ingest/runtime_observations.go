package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func Runtime(ctx context.Context, s *store.Store, k store.NetworkKey, name string, c runtimeobs.Capture) (ObservationResult, error) {
	out := ObservationResult{}
	if !logs.Identifier(name) {
		return out, errors.New("invalid runtime dataset name")
	}
	if e := c.Validate(); e != nil {
		return out, e
	}
	meta, _ := json.Marshal(map[string]string{"normalizer": c.Normalizer, "source_sha256": c.SourceSHA, "node": c.Node, "run": c.Run})
	d, release, e := s.BeginRuntime(ctx, k, name, meta)
	if e != nil {
		return out, e
	}
	defer release()
	out.DatasetID, out.NetworkID = d.ID, d.NetworkID
	if e = s.PutRuntime(ctx, d.ID, c); e != nil {
		return out, e
	}
	out.Calls = int64(len(c.Calls))
	out.Skipped = d.Status == "complete"
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e = s.FinishRange(cleanup, d.ID, int64(len(c.Points)), "")
	return out, e
}
