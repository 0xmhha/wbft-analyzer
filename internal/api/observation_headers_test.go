package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"strings"
	"testing"
)

func TestObservationHeaderReadinessCursorOverlayAndStale(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, sha, e := observe.Load("../source/observe/testdata/capture.json")
	if e != nil {
		t.Fatal(e)
	}
	res, e := ingest.Observations(ctx, s, "synthetic-header-api", "archive", sha, a)
	if e != nil {
		t.Fatal(e)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/observations/headers", res.NetworkID, res.DatasetID)
	if c.do("GET", base+"/index", nil, nil) != 409 {
		t.Fatal("GET rebuilt binding")
	}
	snap, e := observe.Normalize(a)
	if e != nil {
		t.Fatal(e)
	}
	hd, release, e := s.BeginRange(ctx, store.NetworkKey{ChainID: "8", GenesisHash: snap.Node.GenesisHash.String()}, "independent-api-headers", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	facts := []headers.Fact{}
	copies := []headers.Copy{}
	node := "0x0000000000000000000000000000000000000001"
	for i := 0; i < 4; i++ {
		hash := "0x" + strings.Repeat(fmt.Sprint(i+1), 64)
		f := headers.Fact{Index: fmt.Sprint(i), Number: fmt.Sprint(i), Hash: hash, ParentHash: "0x" + strings.Repeat(fmt.Sprint(i), 64), Validators: []string{node}, Policy: "0", LastProposer: node, Coinbase: node, EpochInfo: json.RawMessage(`null`), PrevPrepared: []int64{0}, PrevCommitted: []int64{0}}
		facts = append(facts, f)
		copies = append(copies, headers.Copy{Index: f.Index, Hash: hash, Node: "independent", Prepared: []int64{0}, Committed: []int64{0}})
	}
	if e = s.PutHeaders(ctx, hd.ID, hd.NetworkID, facts, copies, 4); e != nil {
		t.Fatal(e)
	}
	overlay := fmt.Sprintf("/v1/networks/%d/headers?from=1&to=1&dataset=%d&node=%s", res.NetworkID, res.DatasetID, node)
	if c.do("GET", overlay, nil, nil) != 409 {
		t.Fatal("unindexed observation overlay accepted")
	}
	if _, e = s.RebuildObservationHeaders(ctx, res.DatasetID); e != nil {
		t.Fatal(e)
	}
	var p ObservationHeaderPage
	query := "?from=1&to=2&limit=1"
	if c.do("GET", base+query, nil, &p) != 200 || p.Total != 4 || p.Next == nil || len(p.Rows) != 1 {
		t.Fatal(p)
	}
	cursor := *p.Next
	if c.do("GET", base+query+"&cursor="+cursor, nil, &p) != 200 || p.Rows[0].SourceOrdinal != 1 {
		t.Fatal("cursor/original row not preserved", p)
	}
	if c.do("GET", base+"?from=1&to=2&status=unknown&cursor="+cursor, nil, nil) != 400 {
		t.Fatal("cross-filter cursor accepted")
	}
	var hs HeaderList
	if c.do("GET", overlay, nil, &hs) != 200 || hs.Headers[0].Copy == nil || hs.Headers[0].Copy.Source != "rpc_observation_structural" {
		t.Fatal(hs)
	}
	for _, q := range []string{"?from=0&to=2", "?from=1&to=2&kind=bad", "?from=1&to=2&status=bad", "?from=1&to=2&from=1", "?from=1&to=2&limit=0"} {
		if c.do("GET", base+q, nil, nil) == 200 {
			t.Fatal(q)
		}
	}
	if e = s.FinishRange(ctx, res.DatasetID, 99, ""); e != nil {
		t.Fatal(e)
	}
	if c.do("GET", base+query, nil, nil) != 409 || c.do("GET", overlay, nil, nil) != 409 {
		t.Fatal("stale source or overlay accepted")
	}
	if e = s.FinishRange(ctx, res.DatasetID, 5, ""); e != nil {
		t.Fatal(e)
	}
	// Canonical metadata changes stale the comparison and its overlay consumer.
	changed := facts[1]
	changed.Time = "1"
	if e = s.PutHeaders(ctx, hd.ID, hd.NetworkID, []headers.Fact{changed}, []headers.Copy{copies[1]}, 4); e == nil {
		t.Fatal("immutable header overwritten")
	}
	// A separate captured view produces a new source snapshot without changing headers.
	second := a
	second.Replies = append([]observe.Reply(nil), a.Replies...)
	second.Replies[4].Response = json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":null}`)
	other, e := ingest.Observations(ctx, s, "different-api-observation", "archive", strings.Repeat("b", 64), second)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RebuildObservationHeaders(ctx, other.DatasetID); e != nil {
		t.Fatal(e)
	}
	foreign := fmt.Sprintf("/v1/networks/%d/datasets/%d/observations/headers", res.NetworkID, other.DatasetID) + query + "&cursor=" + cursor
	if c.do("GET", foreign, nil, nil) != 400 {
		t.Fatal("cross-source cursor accepted")
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets/%d/observations/headers", res.NetworkID+1, res.DatasetID)+query, nil, nil) != 404 {
		t.Fatal("foreign network accepted")
	}
}
