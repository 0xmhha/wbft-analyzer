package api

import (
	"context"
	"encoding/json"
	"fmt"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"net/url"
	"strings"
	"testing"
)

func TestIssueSourcePagesSnapshotAndFilterBinding(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, e := s.BeginMessages(ctx, store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}, "issue-api", json.RawMessage(`{"clock":{"model":"unknown"}}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	for _, n := range []string{"a", "b"} {
		if e = s.PutMessageInput(ctx, d.ID, source.Summary{ID: n, Node: n}); e != nil {
			t.Fatal(e)
		}
	}
	rs := []source.Record{{Input: "a", File: "frames-synthetic.jsonl", Ordinal: 1, Node: "a", Run: "r", Type: "frame", Dir: "in", Key: "k1", Phase: "PREPARE", Wall: "2020-01-01T00:00:00Z"}, {Input: "b", File: "frames-synthetic.jsonl", Ordinal: 1, Node: "b", Run: "r", Type: "frame", Dir: "in", Key: "k2", Phase: "PREPARE", Wall: "2020-01-01T00:00:00Z"}, {Input: "b", File: "frames-synthetic.jsonl", Ordinal: 2, Node: "b", Run: "r", Type: "frame", Dir: "in", Key: "k3", Phase: "PREPARE", Wall: "2020-01-01T00:00:00Z"}}
	for i := range rs {
		rs[i].Seq = fmt.Sprint(rs[i].Ordinal)
	}
	if e = s.PutMessageRecords(ctx, d.ID, rs, 3); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, d.ID, 3, ""); e != nil {
		t.Fatal(e)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages/issues", d.NetworkID, d.ID)
	if c.do("GET", base, nil, nil) != 409 {
		t.Fatal("unindexed issues accepted")
	}
	index, e := s.RebuildMessagePairs(ctx, d.ID)
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.RebuildMessagePairs(ctx, d.ID)
	if e != nil || index.Snapshot == "" || index.Snapshot != again.Snapshot {
		t.Fatal("identical projection changed snapshot", index.Snapshot, again.Snapshot, e)
	}
	var page MessageIssuePage
	if c.do("GET", base+"?limit=1", nil, &page) != 200 || len(page.Issues) != 1 || page.Next == nil || page.Total != 3 || page.Issues[0].Issue.Source.Ordinal != 1 {
		t.Fatal(page)
	}
	cursor := *page.Next
	if c.do("GET", base+"?limit=1&cursor="+url.QueryEscape(cursor), nil, &page) != 200 || len(page.Issues) != 1 || page.Issues[0].Ordinal != 2 {
		t.Fatal(page)
	}
	for _, q := range []string{"?node=b", "?reason=unknown_peer", "?source_dataset=" + fmt.Sprint(d.ID)} {
		if c.do("GET", base+q+"&cursor="+url.QueryEscape(cursor), nil, nil) != 400 {
			t.Fatal("cross-filter cursor accepted", q)
		}
	}
	if c.do("GET", base+"?node=b&reason=unknown_peer", nil, &page) != 200 || page.Total != 2 {
		t.Fatal(page)
	}
	if c.do("GET", base+"?source_dataset="+fmt.Sprint(d.ID), nil, &page) != 200 || page.Total != 3 {
		t.Fatal("omitted source dataset did not resolve to parent", page)
	}
	if c.do("GET", base+"?reason=missing_key", nil, &page) != 200 || page.Total != 0 || len(page.Issues) != 0 {
		t.Fatal(page)
	}
	for _, q := range []string{"?limit=0", "?limit=1001", "?node=a&node=b", "?cursor=", "?reason=../file", "?source_dataset=0", "?source_dataset=-1", "?phase=PREPARE", "?payload=raw"} {
		if c.do("GET", base+q, nil, nil) != 400 {
			t.Fatal("invalid issue query accepted", q)
		}
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets/%d/messages/issues", d.NetworkID+1, d.ID), nil, nil) != 404 {
		t.Fatal("foreign network accepted")
	}
	extra := rs[0]
	extra.Ordinal = 2
	extra.Seq = "2"
	extra.Key = "new"
	if e = s.PutMessageRecords(ctx, d.ID, []source.Record{extra}, 4); e != nil {
		t.Fatal(e)
	}
	if c.do("GET", base+"?cursor="+url.QueryEscape(cursor), nil, nil) != 409 {
		t.Fatal("stale issue projection accepted")
	}
	if _, e = s.RebuildMessagePairs(ctx, d.ID); e != nil {
		t.Fatal(e)
	}
	if c.do("GET", base+"?cursor="+url.QueryEscape(cursor), nil, nil) != 400 {
		t.Fatal("old snapshot cursor accepted")
	}
}
