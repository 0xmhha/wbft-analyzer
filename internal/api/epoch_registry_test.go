package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestEpochRegistryAPIValidatesPageScopeAndCanonicalIndices(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	handler := (&Server{Store: s}).Handler()
	c := client{t, handler}
	d, release, err := s.BeginRange(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("a", 64)}, "epoch-api-headers", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	facts := []headers.Fact{
		{Index: "19", Number: "19", Hash: "0x" + strings.Repeat("b", 64)},
		{Index: "20", Number: "20", Hash: "0x" + strings.Repeat("c", 64), EpochInfo: json.RawMessage(`{"Candidates":[],"Validators":[]}`)},
		{Index: "18446744073709551615", Number: "36893488147419103231", Hash: "0x" + strings.Repeat("d", 64), EpochInfo: json.RawMessage(`{"Candidates":[],"Validators":[]}`)},
	}
	for _, fact := range facts {
		if err = s.PutHeaders(ctx, d.ID, d.NetworkID, []headers.Fact{fact}, []headers.Copy{{Index: fact.Index, Hash: fact.Hash, Node: "synthetic-api-node"}}, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.FinishRange(ctx, d.ID, 3, ""); err != nil {
		t.Fatal(err)
	}
	release()
	base := fmt.Sprintf("/v1/networks/%d/headers/20/registry-effects", d.NetworkID)
	var page EpochRegistryPage
	if c.do("GET", base, nil, &page) != 200 || page.Status != "available" || page.Index != "20" || page.Total != 0 || len(page.Rows) != 0 || page.Next != nil || len(page.Snapshot) != 64 {
		t.Fatal("empty evidence page", page)
	}
	req := httptest.NewRequest("GET", base, nil)
	req.Host = "127.0.0.1:8080"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("dynamic evidence response may be cached")
	}
	for _, query := range []string{"?limit=0", "?limit=21", "?limit=01", "?limit=1&limit=2", "?unknown=1", "?cursor=", "?cursor=invalid!", "?cursor=x&cursor=y"} {
		if c.do("GET", base+query, nil, nil) != 400 {
			t.Fatal("invalid page filter accepted", query)
		}
	}
	for _, index := range []string{"020", "-1", "18446744073709551616"} {
		if c.do("GET", strings.Replace(base, "/20/", "/"+index+"/", 1), nil, nil) != 400 {
			t.Fatal("noncanonical index accepted", index)
		}
	}
	if c.do("GET", strings.Replace(base, "/20/", "/21/", 1), nil, nil) != 404 {
		t.Fatal("missing canonical header hidden")
	}
	var ordinary EpochRegistryPage
	if c.do("GET", strings.Replace(base, "/20/", "/19/", 1), nil, &ordinary) != 200 || ordinary.Status != "not_epoch" {
		t.Fatal("ordinary header became an epoch", ordinary)
	}
	encode := func(value any) string {
		raw, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	for _, test := range []struct {
		cursor any
		status int
	}{
		{epochRegistryCursor{Scope: page.Snapshot, Offset: 1}, 400},
		{epochRegistryCursor{Scope: page.Snapshot, Offset: -1}, 400},
		{epochRegistryCursor{Scope: strings.Repeat("z", 64)}, 400},
		{epochRegistryCursor{Scope: strings.Repeat("0", 64)}, 409},
		{map[string]any{"scope": page.Snapshot, "offset": 0, "unknown": true}, 400},
		{map[string]any{"scope": page.Snapshot, "offset": 0.5}, 400},
	} {
		if code := c.do("GET", base+"?cursor="+encode(test.cursor), nil, nil); code != test.status {
			t.Fatal("cursor validation", code, test.status)
		}
	}
	current := encode(epochRegistryCursor{Scope: page.Snapshot})
	if c.do("GET", base+"?cursor="+current, nil, nil) != 200 {
		t.Fatal("current page scope refused")
	}
	maximum := strings.Replace(base, "/20/", "/18446744073709551615/", 1)
	if c.do("GET", maximum+"?cursor="+current, nil, nil) != 409 {
		t.Fatal("cursor crossed its canonical epoch header")
	}
	var maxPage EpochRegistryPage
	if c.do("GET", maximum, nil, &maxPage) != 200 || maxPage.Index != "18446744073709551615" {
		t.Fatal("uint64 index was replaced by the full encoded number", maxPage)
	}
}
