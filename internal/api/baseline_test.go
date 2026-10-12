package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/derive/baseline"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/event"
	"strings"
	"testing"
)

func TestBaselineSeparatesMissingClaimsAndRejectsCopiedSources(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ids := []int64{}
	network := int64(0)
	for i := 0; i < 3; i++ {
		d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, fmt.Sprint("r", i), json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		in := logs.InputSummary{ID: "log", Node: "n", Profile: "gstable@740526d03", ProfileSHA256: strings.Repeat("c", 64), SHA256: strings.Repeat(string(rune('a'+i%2)), 64)}
		if err = s.PutLogInput(ctx, d.ID, in); err != nil {
			t.Fatal(err)
		}
		es := []logs.Event{}
		for j := 0; j < 2-i%2; j++ {
			r := "0"
			if i == 1 {
				r = "1"
			}
			es = append(es, logs.Event{Record: event.Record{Kind: event.NewHead, View: &event.View{Seq: fmt.Sprint(j + 1), Round: r}, Fields: map[string]any{}}, Node: in.Node, Input: in.ID, Profile: in.Profile, Run: "r", Line: int64(j + 1), Wall: "2026-10-13T00:00:01Z"})
		}
		if err = s.PutLogEvents(ctx, d.ID, es, int64(len(es))); err != nil {
			t.Fatal(err)
		}
		if err = s.FinishRange(ctx, d.ID, int64(len(es)), ""); err != nil {
			t.Fatal(err)
		}
		release()
		ids = append(ids, d.ID)
		network = d.NetworkID
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/rounds/baseline?from=1&to=2&datasets=", network)
	var out baseline.Summary
	if c.do("GET", base+fmt.Sprintf("%d,%d", ids[0], ids[1]), nil, &out) != 200 || len(out.Runs) != 2 || out.Expected != 2 || out.Runs[1].Observers[0].Missing != 1 {
		t.Fatal(out)
	}
	for _, row := range out.Comparisons {
		if row.Round == "1" && (*row.Mean != .5 || *row.Variance != .5) {
			t.Fatal(row)
		}
	}
	for _, bad := range []string{fmt.Sprintf("%d,%d", ids[0], ids[0]), fmt.Sprintf("%d,%d", ids[0], ids[2]), fmt.Sprint(ids[0]), "1,99999", fmt.Sprintf("%d,%d&node=other", ids[0], ids[1]), fmt.Sprintf("%d,%d&to=100001", ids[0], ids[1])} {
		if c.do("GET", base+bad, nil, nil) != 400 {
			t.Fatal("invalid baseline admitted", bad)
		}
	}
}
