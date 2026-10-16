package api

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestDatasetKindFilterKeepsFollowSourcesScoped(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	key := store.NetworkKey{ChainID: "8", GenesisHash: "synthetic-follow-list"}
	src, release, err := s.BeginFollow(ctx, key, "synthetic-source", json.RawMessage(`{}`), 1, "synthetic-parent")
	if err != nil {
		t.Fatal(err)
	}
	release()
	_, release, err = s.BeginRange(ctx, key, "synthetic-child", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	foreign, release, err := s.BeginFollow(ctx, store.NetworkKey{ChainID: "9", GenesisHash: "synthetic-foreign"}, "synthetic-foreign-source", json.RawMessage(`{}`), 1, "foreign-parent")
	if err != nil {
		t.Fatal(err)
	}
	release()
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets", src.NetworkID)
	var out DatasetList
	if code := c.do("GET", base+"?kind=follow", nil, &out); code != 200 || len(out.Datasets) != 1 || out.Datasets[0].ID != src.ID {
		t.Fatalf("follow filter includes derived or foreign datasets: status=%d rows=%+v", code, out.Datasets)
	}
	if code := c.do("GET", base, nil, &out); code != 200 || len(out.Datasets) != 2 {
		t.Fatal("unfiltered listing changed", code, out)
	}
	if code := c.do("GET", base+"?kind=observations", nil, &out); code != 200 || out.Datasets == nil || len(out.Datasets) != 0 {
		t.Fatal("empty typed list is not an array", code, out)
	}
	if code := c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets?kind=follow", foreign.NetworkID), nil, &out); code != 200 || len(out.Datasets) != 1 || out.Datasets[0].ID != foreign.ID {
		t.Fatal("network filter changed", code, out)
	}
	for _, query := range []string{"?kind=", "?kind=other", "?kind=follow&kind=range", "?kind=follow&unknown=1"} {
		if code := c.do("GET", base+query, nil, nil); code != 400 {
			t.Fatal("invalid dataset filter accepted", query, code)
		}
	}
}
