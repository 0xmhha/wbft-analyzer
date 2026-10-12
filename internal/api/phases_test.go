package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/derive/latency"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/event"
)

func TestPhaseAPIContextClocksAndBoundCursor(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "phases", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	kinds := []event.Kind{event.RoundEnter, event.PreprepareAccept, event.Quorum, event.Quorum, event.FinalizeHandover, event.NewHead}
	for _, node := range []string{"n1", "n2"} {
		in := logs.InputSummary{ID: node, Node: node, Profile: "wbft@123456789012", ProfileSHA256: strings.Repeat("c", 64), SHA256: strings.Repeat("a", 64)}
		if err = s.PutLogInput(ctx, d.ID, in); err != nil {
			t.Fatal(err)
		}
		es := []logs.Event{}
		for i, kind := range kinds {
			mono := fmt.Sprint(i * 10000000)
			e := logs.Event{Record: event.Record{Kind: kind, View: &event.View{Seq: "18446744073709551617", Round: "340282366920938463463374607431768211456"}, Fields: map[string]any{}}, Node: node, Input: node, Run: "r1", Profile: in.Profile, Line: int64(i + 1), Wall: fmt.Sprintf("2026-10-13T00:00:00.%dZ", i), Mono: &mono}
			if i == 2 {
				e.Record.Fields["what"] = "PREPARE"
			}
			if i == 3 {
				e.Record.Fields["what"] = "COMMIT"
			}
			es = append(es, e)
		}
		if err = s.PutLogEvents(ctx, d.ID, es, 12); err != nil {
			t.Fatal(err)
		}
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/phases", d.NetworkID, d.ID)
	q := "?from_t=2026-10-13T00:00:00.05Z&to_t=2026-10-13T00:00:01Z&metric=preprepare"
	var sum latency.Summary
	if c.do("GET", base+"/summary"+q, nil, &sum) != 200 || sum.Samples != 2 {
		t.Fatal(sum)
	}
	for _, g := range sum.Groups {
		if g.Valid != g.Total || g.Clock != "monotonic" || g.P99 == nil || *g.P99 != .01 {
			t.Fatal(g)
		}
	}
	var page PhasePage
	if c.do("GET", base+"/samples"+q+"&clock=monotonic&threshold=p95&limit=1", nil, &page) != 200 || page.Total != 2 || len(page.Samples) != 1 || page.Next == nil {
		t.Fatal(page)
	}
	first := page.Samples[0]
	if first.Start == nil || first.Start.Line != 1 || first.End.Line != 2 || first.Status != "valid" {
		t.Fatal(first)
	}
	cursor := url.QueryEscape(*page.Next)
	if c.do("GET", base+"/samples"+q+"&clock=monotonic&threshold=p95&cursor="+cursor, nil, &page) != 200 || len(page.Samples) != 1 || page.Next != nil || page.Samples[0].ID == first.ID {
		t.Fatal(page)
	}
	for _, suffix := range []string{"&node=n2", "&round=0", "&status=negative"} {
		if c.do("GET", base+"/samples"+q+"&clock=monotonic&threshold=p95&cursor="+cursor+suffix, nil, nil) != 400 {
			t.Fatal("cursor reused", suffix)
		}
	}
	for _, suffix := range []string{"&metric=bad", "&clock=bad", "&status=bad", "&threshold=p95", "&clock=wall&threshold=p75", "&cursor=invalid"} {
		if c.do("GET", base+"/samples"+q+suffix, nil, nil) != 400 {
			t.Fatal("invalid query", suffix)
		}
	}
	if c.do("GET", base+"/samples"+q+"&clock=wall&threshold=p95", nil, &page) != 200 || page.Total != 0 {
		t.Fatal("unavailable clock invented samples", page)
	}
	// Appending source records cannot silently shift an existing cursor page.
	appended := logs.Event{Record: event.Record{Kind: event.RoundEnter, View: &event.View{Seq: "8", Round: "0"}, Fields: map[string]any{}}, Input: "n1", Node: "n1", Run: "r1", Profile: "wbft@123456789012", Line: 7, Wall: "2026-10-13T00:00:00.8Z"}
	if err = s.PutLogEvents(ctx, d.ID, []logs.Event{appended}, 13); err != nil {
		t.Fatal(err)
	}
	if c.do("GET", base+"/samples"+q+"&clock=monotonic&threshold=p95&cursor="+cursor, nil, nil) != 400 {
		t.Fatal("cursor reused after source append")
	}

}
