package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/event"
)

func TestBuildLifecycleAPIRetainsSourceAndExactFilter(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}, "build-api", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	node := "0x" + strings.Repeat("1", 40)
	err = s.PutLogInput(ctx, d.ID, logs.InputSummary{ID: "input", Node: node, Kind: "events", Profile: logs.EventProfile, SHA256: strings.Repeat("a", 64), ProfileSHA256: strings.Repeat("b", 64), Bytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishLogInput(ctx, d.ID, "input", logs.Stats{Events: 3}); err != nil {
		t.Fatal(err)
	}
	rows := []logs.Event{}
	for i, kind := range []event.Kind{event.BuildHandover, event.BuildStarted, event.BuildFinished} {
		mono := strconv.Itoa(i * 20)
		fields := map[string]any{"build_id": "build-1", "number": "18446744073709551616", "wait_ns": "10"}
		if kind == event.BuildFinished {
			fields["status"] = "submitted"
			fields["hash"] = "0x" + strings.Repeat("a", 64)
		}
		rows = append(rows, logs.Event{Node: node, Input: "input", Run: "run", Wall: "2026-01-01T00:00:00Z", Profile: logs.EventProfile, Level: "event", Line: int64(i + 1), Mono: &mono, Record: event.Record{Kind: kind, Src: "event", View: &event.View{Seq: "18446744073709551616", Round: "0"}, Fields: fields}})
	}
	if err = s.PutLogEvents(ctx, d.ID, rows, 3); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, d.ID, 3, ""); err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d", d.NetworkID, d.ID)
	var out store.BuildLifecycle
	if c.do("GET", base+"/events/input/2/build", nil, &out) != 200 || out.State != "complete" || out.Origin.Line != 2 || len(out.Events) != 3 || out.AssemblyNS == nil || *out.AssemblyNS != "20" {
		t.Fatal(out)
	}
	if c.do("GET", base+"/events/other/2/build", nil, nil) != 404 || c.do("GET", base+"/events/input/0/build", nil, nil) != 400 {
		t.Fatal("invalid source allowed")
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets/%d/events/input/2/build", d.NetworkID+1, d.ID), nil, nil) != 404 {
		t.Fatal("cross-network source allowed")
	}
	var page LogEventPage
	if c.do("GET", base+"/events?from_t=2026-01-01T00:00:00Z&to_t=2026-01-01T00:00:01Z&kind=BUILD_STARTED", nil, &page) != 200 || len(page.Events) != 1 || page.Events[0].Line != 2 {
		t.Fatal("native kind filter rejected", page)
	}
}
