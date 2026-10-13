package api

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestFollowStateScopeAndOriginalCompanions(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, e := s.BeginFollow(ctx, store.NetworkKey{ChainID: "8", GenesisHash: "0xsynthetic"}, "synthetic-follow", json.RawMessage(`{"address":"synthetic-node"}`), 1, "synthetic-parent")
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	c := client{t, (&Server{Store: s}).Handler()}
	path := fmt.Sprintf("/v1/networks/%d/datasets/%d/follow", d.NetworkID, d.ID)
	var out store.FollowState
	if c.do("GET", path, nil, &out) != 200 || out.Cursor.Next != "1" || out.Cursor.ParentHash != "synthetic-parent" || out.Captured != 0 || out.TotalBatches != 0 || out.Latest == nil {
		t.Fatal(out)
	}
	var refused json.RawMessage
	if c.do("GET", path+"?cursor=1", nil, &refused) != 400 {
		t.Fatal("unrecognized filter accepted")
	}
	foreign := fmt.Sprintf("/v1/networks/%d/datasets/%d/follow", d.NetworkID+1, d.ID)
	if c.do("GET", foreign, nil, &refused) != 404 {
		t.Fatal("foreign network exposed cursor")
	}
}
