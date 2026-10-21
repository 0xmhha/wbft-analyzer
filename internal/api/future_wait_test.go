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

func TestFutureWaitHealthAPIPreservesNormalRecordedLengths(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	metadata, err := json.Marshal(map[string]string{"events_normalizer": logs.EventNormalizer})
	if err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}, "future-wait-evidence", metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	node := "0x" + strings.Repeat("1", 40)
	if err = s.PutLogInput(ctx, d.ID, logs.InputSummary{ID: "wait-events", Node: node, Kind: "events", Profile: logs.EventProfile, SHA256: strings.Repeat("a", 64), ProfileSHA256: strings.Repeat("b", 64), Bytes: 200}); err != nil {
		t.Fatal(err)
	}
	rows := []logs.Event{}
	for i, origin := range []string{"preprepare", "local_reproposal"} {
		mono := strconv.Itoa(i + 1)
		fields := map[string]any{"what": "future_proposal_wait_exceeded", "h": "18446744073709551616", "hash": "0x" + strings.Repeat("a", 64), "proposal_origin": origin, "wait_ns": "9007199254740993", "limit_ns": "9007199254740992"}
		rows = append(rows, logs.Event{Node: node, Input: "wait-events", Run: "normal-wait-1", Wall: "2026-01-01T00:00:00Z", Profile: logs.EventProfile, Level: "event", Line: int64(i + 1), Mono: &mono, Record: event.Record{Kind: event.Health, Src: "event", View: &event.View{Seq: "18446744073709551616", Round: "1"}, Fields: fields}})
	}
	if err = s.PutLogEvents(ctx, d.ID, rows, 2); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishLogInput(ctx, d.ID, "wait-events", logs.Stats{Events: 2}); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, d.ID, 2, ""); err != nil {
		t.Fatal(err)
	}
	client := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d", d.NetworkID, d.ID)
	for i, origin := range []string{"preprepare", "local_reproposal"} {
		var out store.LogEvent
		if client.do("GET", fmt.Sprintf("%s/events/wait-events/%d", base, i+1), nil, &out) != 200 {
			t.Fatal("normal source unavailable")
		}
		var fields map[string]any
		if err = json.Unmarshal(out.Fields, &fields); err != nil {
			t.Fatal(err)
		}
		if out.Kind != event.Health || out.Height != "18446744073709551616" || out.Round != "1" || out.Input != "wait-events" || out.Run != "normal-wait-1" || out.Line != int64(i+1) || fields["proposal_origin"] != origin || fields["wait_ns"] != "9007199254740993" || fields["limit_ns"] != "9007199254740992" || fields["what"] != "future_proposal_wait_exceeded" {
			t.Fatal("stored normal metadata changed", out, fields)
		}
	}
	var page LogEventPage
	if client.do("GET", base+"/events?from_t=2026-01-01T00:00:00Z&to_t=2026-01-01T00:00:01Z&kind=HEALTH", nil, &page) != 200 || len(page.Events) != 2 {
		t.Fatal(page)
	}
}
