package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/event"
)

func TestMissingCursorScopeReadinessAndEvidence(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	key := store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}
	hd, release, e := s.BeginRange(ctx, key, "missing-headers", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	members := []string{}
	for i := 1; i <= 4; i++ {
		members = append(members, fmt.Sprintf("0x%040x", i))
	}
	facts := []headers.Fact{}
	copies := []headers.Copy{}
	for i := 1; i <= 3; i++ {
		f := headers.Fact{Index: fmt.Sprint(i), Number: fmt.Sprint(i), Hash: "0x" + strings.Repeat(fmt.Sprint(i), 64), ParentHash: "0x" + strings.Repeat(fmt.Sprint(i-1), 64), Validators: members, Policy: "0", EpochInfo: json.RawMessage(`null`), PrevPrepared: []int64{0, 1, 2}, PrevCommitted: []int64{0, 1, 2}}
		facts = append(facts, f)
		copies = append(copies, headers.Copy{Index: f.Index, Hash: f.Hash, Node: "observer", Prepared: []int64{0, 1, 2}, Committed: []int64{0, 1, 2}})
	}
	if e = s.PutHeaders(ctx, hd.ID, hd.NetworkID, facts, copies, 3); e != nil {
		t.Fatal(e)
	}
	d, release, e := s.BeginRun(ctx, key, "missing-run", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	n := members[3]
	if e = s.PutLogInput(ctx, d.ID, logs.InputSummary{ID: "events", Node: n, Kind: "events", Profile: logs.EventProfile, SHA256: strings.Repeat("a", 64), ProfileSHA256: strings.Repeat("b", 64)}); e != nil {
		t.Fatal(e)
	}
	rows := []logs.Event{}
	for i, k := range []event.Kind{event.NodeStart, event.RoundEnter, event.RoundEnter, event.NodeStop} {
		var v *event.View
		if k == event.RoundEnter {
			v = &event.View{Seq: fmt.Sprint(i), Round: "0"}
		}
		rows = append(rows, logs.Event{Input: "events", Node: n, Run: "r", Line: int64(i + 1), Wall: "2020-01-01T00:00:00Z", Profile: logs.EventProfile, Record: event.Record{Src: "event", Kind: k, View: v, Fields: map[string]any{"seq": fmt.Sprint(i), "validator": true}}})
	}
	if e = s.PutLogEvents(ctx, d.ID, rows, 4); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, d.ID, 4, ""); e != nil {
		t.Fatal(e)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/missing", d.NetworkID, d.ID)
	if c.do("GET", base+"/index", nil, nil) != 409 {
		t.Fatal("GET silently created index")
	}
	if _, e = s.RebuildMissing(ctx, d.ID, 0, 1, 2); e != nil {
		t.Fatal(e)
	}
	var index store.MissingIndex
	if c.do("GET", base+"/index", nil, &index) != 200 || index.Cells != 16 {
		t.Fatal(index)
	}
	var p MissingPage
	query := "?from=1&to=2&class=NOT_SENT&limit=1"
	if c.do("GET", base+query, nil, &p) != 200 || p.Total != 4 || len(p.Cells) != 1 || p.Next == nil || p.Cells[0].Evidence[0].Source.DatasetID != d.ID {
		t.Fatal(p)
	}
	cursor := *p.Next
	first := p.Cells[0]
	if c.do("GET", base+query+"&cursor="+cursor, nil, &p) != 200 || p.Cells[0].Index == first.Index && p.Cells[0].Phase == first.Phase {
		t.Fatal("cursor repeated cell", p)
	}
	if c.do("GET", base+"?from=1&to=2&class=SEALED&cursor="+cursor, nil, nil) != 400 {
		t.Fatal("cross-filter cursor accepted")
	}
	for _, q := range []string{"?from=1&to=2&phase=bad", "?from=1&to=2&class=bad", "?from=1&to=2&validator=bad", "?from=1&to=2&limit=0", "?from=1&to=2&from=1", "?from=1&to=2&events=1", "?from=1&to=3", "?from=1"} {
		if c.do("GET", base+q, nil, nil) == 200 {
			t.Fatal("invalid scope accepted", q)
		}
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets/%d/missing", d.NetworkID+1, d.ID)+query, nil, nil) != 404 {
		t.Fatal("foreign network accepted")
	}
	extra := rows[3]
	extra.Line = 5
	extra.Record.Fields = map[string]any{"seq": "4"}
	if e = s.PutLogEvents(ctx, d.ID, []logs.Event{extra}, 5); e != nil {
		t.Fatal(e)
	}
	if c.do("GET", base+query, nil, nil) != 409 {
		t.Fatal("source append did not invalidate")
	}
	if _, e = s.RebuildMissing(ctx, d.ID, 0, 1, 2); e != nil {
		t.Fatal(e)
	}
	if c.do("GET", base+query+"&cursor="+cursor, nil, nil) != 400 {
		t.Fatal("old snapshot cursor accepted")
	}
}
