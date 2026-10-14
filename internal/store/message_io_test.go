package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	derived "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func TestStoredIOMetricKeepsRawMetricSelectorsAndDuplicateCandidates(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	d, release, e := s.BeginMessages(ctx, NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}, "io-metrics", json.RawMessage(`{"clock":{"model":"shared-host"}}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	for _, n := range []string{"a", "b"} {
		if e := s.PutMessageInput(ctx, d.ID, source.Summary{ID: n, Node: n}); e != nil {
			t.Fatal(e)
		}
	}
	a := source.Record{Input: "a", File: "f", Ordinal: 1, Seq: "1", Node: "a", Run: "r", Type: "frame", Dir: "out", Peer: "b", Key: "bytes", Phase: "COMMIT", Height: "1", Round: "0", Write: "ok", Wall: "2020-01-01T00:00:00.020Z", IO: &source.IOInterval{StartWall: "2020-01-01T00:00:00Z", EndWall: "2020-01-01T00:00:00.010Z", StartMono: "0", EndMono: "10000000"}}
	b := a
	b.Input = "b"
	b.Node = "b"
	b.Peer = "a"
	b.Dir = "in"
	b.Wall = "2020-01-01T00:00:00.006Z"
	b.IO = &source.IOInterval{StartWall: "2019-12-31T23:59:59Z", EndWall: "2020-01-01T00:00:00.005Z", StartMono: "0", EndMono: "1005000000"}
	if e := s.PutMessageRecords(ctx, d.ID, []source.Record{a, b}, 2); e != nil {
		t.Fatal(e)
	}
	if e := s.FinishRange(ctx, d.ID, 2, ""); e != nil {
		t.Fatal(e)
	}
	index, e := s.RebuildMessagePairs(ctx, d.ID)
	if e != nil || index.Pairs != 2 {
		t.Fatal(index, e)
	}
	_, old, e := s.MessagePairData(ctx, d.ID, PairFilter{Metric: "link"})
	if e != nil || len(old) != 1 || old[0].Status != "negative" {
		t.Fatal(old, e)
	}
	_, io, e := s.MessagePairData(ctx, d.ID, PairFilter{Metric: derived.WriteStartToReadComplete})
	if e != nil || len(io) != 1 || io[0].Status != "valid" || *io[0].Seconds != .005 {
		t.Fatal(io, e)
	}
	selected, e := s.MessageRecordAt(ctx, d.ID, io[0].Send.Input, io[0].Send.File, io[0].Send.Ordinal)
	if e != nil || selected.Wall != a.Wall || io[0].Send.CallbackWall != a.Wall {
		t.Fatal("selector returned projected clock instead of original", selected, e)
	}
	repeat := a
	repeat.Ordinal = 2
	repeat.Seq = "2"
	repeat.IO = nil
	if e := s.PutMessageRecords(ctx, d.ID, []source.Record{repeat}, 3); e != nil {
		t.Fatal(e)
	}
	if _, e := s.RebuildMessagePairs(ctx, d.ID); e != nil {
		t.Fatal(e)
	}
	_, io, e = s.MessagePairData(ctx, d.ID, PairFilter{Metric: derived.WriteStartToReadComplete})
	if e != nil || len(io) != 1 || io[0].Status != "ambiguous" || io[0].SendCandidates != 2 {
		t.Fatal("unmeasured duplicate disappeared from stored metric", io, e)
	}
}
