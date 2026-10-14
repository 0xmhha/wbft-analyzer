package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

func TestNetworkEvidencePagesRemainScopedAndKeepOriginalCoordinates(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-network-api", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = s.PutMessageInput(ctx, d.ID, messages.Summary{ID: "journal", Kind: "journal", Node: "node", SHA256: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	seconds := "2"
	id, err := s.BeginWhatif(ctx, store.WhatifRun{Dataset: d.ID, Input: "journal", SourceSHA: strings.Repeat("a", 64), ChainSHA: strings.Repeat("b", 64), HelperSHA: strings.Repeat("c", 64), Policy: whatif.Policy{Request: &seconds}}, "private")
	if err != nil {
		t.Fatal(err)
	}
	q := whatif.Question{Source: whatif.Source{Writer: "synthetic", Engine: "18446744073709551615", Step: "9007199254740993", Ordinal: "3"}, Output: "1"}
	bindings := []whatif.NetworkBinding{{Original: q, Kind: "broadcast", Sender: "0x" + strings.Repeat("1", 40), Recipient: "0x" + strings.Repeat("2", 40), Status: "missing_send"}, {Original: q, Kind: "broadcast", Sender: "0x" + strings.Repeat("1", 40), Recipient: "0x" + strings.Repeat("3", 40), Status: "unknown_clock"}}
	if err = s.PutWhatifNetworkBindings(ctx, id, bindings); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 2; index++ {
		if err = s.PutWhatifNetworkEffects(ctx, id, []whatif.NetworkEffect{{ID: fmt.Sprint(index), Kind: "removed", Status: "original_delivery_unproved", Original: &q, ActionKind: "broadcast", Bindings: []string{fmt.Sprint(index)}}}); err != nil {
			t.Fatal(err)
		}
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/whatif/%d", d.NetworkID, d.ID, id)
	var page WhatifNetworkBindingPage
	if c.do("GET", base+"/network-bindings?limit=1", nil, &page) != 200 || len(page.Bindings) != 1 || page.Next == nil || page.Bindings[0].Evidence.Original.Source.Engine != q.Source.Engine {
		t.Fatal(page)
	}
	var effects WhatifNetworkEffectPage
	if c.do("GET", base+"/network-effects?after=1&limit=1", nil, &effects) != 200 || len(effects.Effects) != 1 || effects.Next != nil || effects.Effects[0].Current != nil {
		t.Fatal(effects)
	}
	for _, path := range []string{"network-bindings", "network-effects"} {
		for _, query := range []string{"?after=-1", "?limit=1001", "?after=1&after=2", "?payload=raw"} {
			if c.do("GET", base+"/"+path+query, nil, nil) != 400 {
				t.Fatal(path, query)
			}
		}
		if c.do("GET", fmt.Sprintf("/v1/networks/999/datasets/%d/whatif/%d/%s", d.ID, id, path), nil, nil) != 404 {
			t.Fatal("foreign evidence exposed")
		}
	}
}
