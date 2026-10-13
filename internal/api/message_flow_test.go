package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/event"
	"strings"
	"testing"
)

func TestFlowOverlapsWholeEvidenceAndRequiresEventExecution(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, e := s.BeginRun(ctx, store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}, "flow", json.RawMessage(`{"clock":"shared-host"}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	a, b := "0x0000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000002"
	for _, n := range []string{a, b} {
		if e = s.PutLogInput(ctx, d.ID, logs.InputSummary{ID: n, Node: n, Kind: "events", Profile: "wbft@events-v1", SHA256: strings.Repeat("b", 64), ProfileSHA256: strings.Repeat("c", 64)}); e != nil {
			t.Fatal(e)
		}
	}
	key := "0x" + strings.Repeat("a", 64)
	events := []logs.Event{{Input: a, Node: a, Run: "r", Line: 1, Wall: "2020-01-01T00:00:00Z", Profile: "wbft@events-v1", Record: event.Record{Src: "event", Kind: event.Send, Fields: map[string]any{"code": "19", "cause": "broadcast", "dedup_key": key}}}, {Input: b, Node: b, Run: "r", Line: 1, Wall: "2020-01-01T00:00:00.020Z", Profile: "wbft@events-v1", Record: event.Record{Src: "event", Kind: event.MsgOutcome, View: &event.View{Seq: "18446744073709551617", Round: "0"}, Fields: map[string]any{"code": "19", "source": a, "dedup_key": key, "outcome": "ACCEPT"}}}}
	if e = s.PutLogEvents(ctx, d.ID, events, 2); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, d.ID, 2, ""); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RebuildMessagePairs(ctx, d.ID); e != nil {
		t.Fatal(e)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages", d.NetworkID, d.ID)
	window := "?from_t=2020-01-01T00:00:00.010Z&to_t=2020-01-01T00:00:00.015Z&receiver=" + b
	var flow MessageFlow
	if c.do("GET", base+"/flow"+window+"&events="+fmt.Sprint(d.ID), nil, &flow) != 200 || len(flow.Pairs) != 1 || flow.Pairs[0].ReceiveCandidates != 1 || flow.Pairs[0].Height != "18446744073709551617" {
		t.Fatal("in-flight overlap was lost", flow)
	}
	var page PairPage
	if c.do("GET", base+"/pairs"+window, nil, &page) != 200 || len(page.Pairs) != 0 {
		t.Fatal("send-at sample filtering changed", page)
	}
	for _, extra := range []string{"&events=0", "&events=9999", "&events=1&limit=1", "&events=1&threshold=p95", "&events=1&cursor=bad", "&events=1&events=1"} {
		if c.do("GET", base+"/flow"+window+extra, nil, nil) == 200 {
			t.Fatal("invalid flow query accepted", extra)
		}
	}
	if c.do("GET", base+"/flow?events="+fmt.Sprint(d.ID), nil, nil) != 400 {
		t.Fatal("unbounded flow accepted")
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets/%d/messages/flow", d.NetworkID+1, d.ID)+window+"&events="+fmt.Sprint(d.ID), nil, nil) != 404 {
		t.Fatal("foreign flow accepted")
	}
	if e = s.PutLogEvents(ctx, d.ID, []logs.Event{{Input: a, Node: a, Run: "r", Line: 2, Wall: events[0].Wall, Profile: "wbft@events-v1", Record: events[0].Record}}, 3); e != nil {
		t.Fatal(e)
	}
	if c.do("GET", base+"/flow"+window+"&events="+fmt.Sprint(d.ID), nil, nil) != 409 {
		t.Fatal("stale flow accepted")
	}
	if _, e = s.RebuildMessagePairs(ctx, d.ID); e != nil {
		t.Fatal(e)
	}
	if c.do("GET", base+"/flow"+window+"&events="+fmt.Sprint(d.ID), nil, &flow) != 200 || flow.Pairs[0].Status != "ambiguous" || flow.Pairs[0].SendCandidates != 2 {
		t.Fatal("out-of-window retry became unique", flow)
	}
}

func TestFlowRejectsOversizedWindowInsteadOfTruncating(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}, "flow-cap", json.RawMessage(`{"clock":"shared-host"}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	a, b := "0x0000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000002"
	for _, n := range []string{a, b} {
		if err = s.PutLogInput(ctx, d.ID, logs.InputSummary{ID: n, Node: n, Kind: "events", Profile: "wbft@events-v1", SHA256: strings.Repeat("b", 64), ProfileSHA256: strings.Repeat("c", 64)}); err != nil {
			t.Fatal(err)
		}
	}
	rows := make([]logs.Event, 0, 4002)
	for i := 1; i <= 2001; i++ {
		key := fmt.Sprintf("0x%064x", i)
		rows = append(rows, logs.Event{Input: a, Node: a, Run: "r", Line: int64(i), Wall: "2020-01-01T00:00:00Z", Profile: "wbft@events-v1", Record: event.Record{Src: "event", Kind: event.Send, Fields: map[string]any{"code": "19", "cause": "broadcast", "dedup_key": key}}}, logs.Event{Input: b, Node: b, Run: "r", Line: int64(i), Wall: "2020-01-01T00:00:00.020Z", Profile: "wbft@events-v1", Record: event.Record{Src: "event", Kind: event.MsgOutcome, View: &event.View{Seq: "1", Round: "0"}, Fields: map[string]any{"code": "19", "source": a, "dedup_key": key, "outcome": "ACCEPT"}}})
	}
	if err = s.PutLogEvents(ctx, d.ID, rows, int64(len(rows))); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, d.ID, int64(len(rows)), ""); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RebuildMessagePairs(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	url := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages/flow?events=%d&from_t=2020-01-01T00:00:00Z&to_t=2020-01-01T00:00:01Z", d.NetworkID, d.ID, d.ID)
	if c.do("GET", url, nil, nil) != 400 {
		t.Fatal("oversized flow silently truncated")
	}
}
