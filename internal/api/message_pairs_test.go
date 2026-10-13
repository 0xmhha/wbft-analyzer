package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"net/url"
	"strings"
	"testing"
)

func TestPairPagesThresholdEvidenceAndStaleSnapshot(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, e := s.BeginMessages(ctx, store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}, "pair-api", json.RawMessage(`{"clock":{"model":"shared-host"}}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	a, b := "0x0000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000002"
	for _, n := range []string{a, b} {
		if e = s.PutMessageInput(ctx, d.ID, messages.Summary{ID: n, Node: n}); e != nil {
			t.Fatal(e)
		}
	}
	records := []messages.Record{}
	for i := 1; i <= 3; i++ {
		key := fmt.Sprintf("0x%064x", i)
		records = append(records,
			messages.Record{Input: a, File: "00000000000000000000.wal", Ordinal: int64(i), Node: a, Run: "run", Seq: fmt.Sprint(i), Type: "frame", Dir: "out", Peer: b, Key: key, Phase: "PREPARE", Height: "18446744073709551617", Round: "0", Wall: "2020-01-01T00:00:00Z", Write: "ok"},
			messages.Record{Input: b, File: "00000000000000000000.wal", Ordinal: int64(i), Node: b, Run: "run", Seq: fmt.Sprint(i), Type: "frame", Dir: "in", Peer: a, Key: key, Phase: "PREPARE", Height: "18446744073709551617", Round: "0", Wall: fmt.Sprintf("2020-01-01T00:00:00.%03dZ", i*10)},
		)
	}
	if e = s.PutMessageRecords(ctx, d.ID, records, 6); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, d.ID, 6, ""); e != nil {
		t.Fatal(e)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages", d.NetworkID, d.ID)
	if c.do("GET", base+"/pairs", nil, nil) != 409 {
		t.Fatal("missing index accepted")
	}
	if _, e = s.RebuildMessagePairs(ctx, d.ID); e != nil {
		t.Fatal(e)
	}
	var summary PairSummary
	if c.do("GET", base+"/summary", nil, &summary) != 200 || summary.Summary.Pairs != 3 || summary.Index.Records != 6 {
		t.Fatal(summary)
	}
	var series PairTimeSeries
	if c.do("GET", base+"/series", nil, &series) != 200 || series.Series.Pairs != 3 || len(series.Series.Points) != 1 {
		t.Fatal(series)
	}
	if c.do("GET", base+"/series?limit=1", nil, nil) != 400 {
		t.Fatal("series sample paging accepted")
	}
	if c.do("GET", base+"/series?metric=broadcast_to_receipt", nil, &series) != 200 || series.Series.Pairs != 0 {
		t.Fatal("boundary metrics mixed", series)
	}
	var page PairPage
	if c.do("GET", base+"/pairs?limit=1", nil, &page) != 200 || len(page.Pairs) != 1 || page.Next == nil || page.Total != 3 || page.Pairs[0].Send == nil {
		t.Fatal(page)
	}
	cursor := *page.Next
	if c.do("GET", base+"/pairs?limit=1&cursor="+url.QueryEscape(cursor), nil, &page) != 200 || len(page.Pairs) != 1 {
		t.Fatal(page)
	}
	for _, q := range []string{"?strength=link", "?height=18446744073709551617", "?phase=PREPARE", "?sender=" + a} {
		if c.do("GET", base+"/pairs"+q+"&cursor="+url.QueryEscape(cursor), nil, nil) != 400 {
			t.Fatal("cross-filter cursor accepted", q)
		}
	}
	for _, q := range []string{"?limit=1001", "?limit=1&limit=2", "?phase=unknown", "?strength=strong", "?clock=wall", "?sender=../file", "?height=-1", "?from_t=2020-01-01T00:00:00Z", "?threshold=p95", "?payload=raw"} {
		if c.do("GET", base+"/pairs"+q, nil, nil) != 400 {
			t.Fatal("invalid query accepted", q)
		}
	}
	q := "?phase=PREPARE&strength=link&path=direct&clock=shared-host&threshold=p95"
	if c.do("GET", base+"/pairs"+q, nil, &page) != 200 || page.Threshold == nil || *page.Threshold != .03 || len(page.Pairs) != 1 || page.Pairs[0].Receive.Ordinal != 3 {
		t.Fatal(page)
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets/%d/messages/pairs", d.NetworkID+1, d.ID), nil, nil) != 404 {
		t.Fatal("foreign network accepted")
	}
	repeat := records[0]
	repeat.Ordinal = 4
	repeat.Seq = "4"
	repeat.Wall = "2020-01-01T01:00:00Z"
	if e = s.PutMessageRecords(ctx, d.ID, []messages.Record{repeat}, 7); e != nil {
		t.Fatal(e)
	}
	if c.do("GET", base+"/pairs?cursor="+url.QueryEscape(cursor), nil, nil) != 409 {
		t.Fatal("stale index accepted")
	}
	if _, e = s.RebuildMessagePairs(ctx, d.ID); e != nil {
		t.Fatal(e)
	}
	if c.do("GET", base+"/pairs?cursor="+url.QueryEscape(cursor), nil, nil) != 400 {
		t.Fatal("old snapshot cursor accepted")
	}
}
