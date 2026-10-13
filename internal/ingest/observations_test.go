package ingest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestObservationImportIdentityIdempotenceAndTypedSources(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, sha, e := observe.Load("../source/observe/testdata/capture.json")
	if e != nil {
		t.Fatal(e)
	}
	r, e := Observations(ctx, s, "synthetic-observations", "archive", sha, a)
	if e != nil || r.Calls != 5 || r.Skipped || r.Comparison != "match" {
		t.Fatal(r, e)
	}
	again, e := Observations(ctx, s, "synthetic-observations", "archive", sha, a)
	if e != nil || !again.Skipped || again.DatasetID != r.DatasetID {
		t.Fatal(again, e)
	}
	info, e := s.ObservationCapture(ctx, r.DatasetID)
	if e != nil || info.Node.Address != "0x0000000000000000000000000000000000000001" || info.SourceSHA256 != sha {
		t.Fatal(info, e)
	}
	rows, total, e := s.ObservationRows(ctx, r.DatasetID, "1", "2", 0, 1)
	if e != nil || total != 2 || len(rows) != 2 || rows[0].Source != "header" || rows[0].LocalArrivals != 0 || !rows[1].Gap || rows[0].CallOrdinal != 2 || rows[0].SourceOrdinal != 1 {
		t.Fatal(rows, total, e)
	}
	call, e := s.ObservationCall(ctx, r.DatasetID, rows[0].CallOrdinal)
	if e != nil || call.Method != "wbft_participation" {
		t.Fatal(call, e)
	}
	ds, e := s.Datasets(ctx, r.NetworkID)
	if e != nil || len(ds) != 1 || ds[0].Kind != "observations" || len(ds[0].Nodes) != 1 {
		t.Fatal(ds, e)
	}
	if _, e = Observations(ctx, s, "synthetic-observations", "rpc", sha, a); e == nil {
		t.Fatal("source replacement accepted")
	}
	snap, e := observe.Normalize(a)
	if e != nil {
		t.Fatal(e)
	}
	snap.Node.ChainID.SetInt64(9)
	if e = s.PutObservation(ctx, r.DatasetID, "archive", sha, snap); e == nil {
		t.Fatal("foreign node identity accepted")
	}
	unchanged, e := s.ObservationCapture(ctx, r.DatasetID)
	if e != nil || unchanged.Snapshot != info.Snapshot {
		t.Fatal("failed store destroyed capture", unchanged, e)
	}
	bad, release, e := s.BeginObservations(ctx, store.NetworkKey{ChainID: "9", GenesisHash: info.Node.GenesisHash}, "unrelated-observation", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	snap.Node.ChainID.SetInt64(8)
	if e = s.PutObservation(ctx, bad.ID, "archive", sha, snap); e == nil {
		t.Fatal("dataset/node identity mismatch accepted")
	}
	if _, _, e = s.ObservationRows(ctx, r.DatasetID, "0", "2", 0, 10); e == nil {
		t.Fatal("foreign range accepted")
	}
}
