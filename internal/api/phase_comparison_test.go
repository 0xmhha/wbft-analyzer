package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/derive/latency"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/event"
)

func TestPhaseComparisonLogicalRangeAndEvidence(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ids := []int64{}
	var network int64
	for i := range 5 {
		chain := "77"
		genesis := "0x" + strings.Repeat("1", 64)
		if i == 3 {
			genesis = "0x" + strings.Repeat("2", 64)
		}
		d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: chain, GenesisHash: genesis}, fmt.Sprintf("phase-run-%d", i), json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		profile := "wbft@123456789012"
		if i == 1 {
			profile = "gstable@123456789012"
		}
		digit := "a"
		if i != 0 && i != 2 {
			digit = fmt.Sprint(i)
		}
		in := logs.InputSummary{ID: "input", Node: "n1", Profile: profile, ProfileSHA256: strings.Repeat("c", 64), SHA256: strings.Repeat(digit, 64)}
		if err = s.PutLogInput(ctx, d.ID, in); err != nil {
			t.Fatal(err)
		}
		es := []logs.Event{}
		wall := time.Date(2030+i, 1, 1, 0, 0, 0, 0, time.UTC)
		add := func(kind event.Kind, height string, ns *int64) {
			line := int64(len(es) + 1)
			var mono *string
			if ns != nil {
				value := fmt.Sprint(*ns)
				mono = &value
			}
			var view *event.View
			if height != "" {
				view = &event.View{Seq: height, Round: fmt.Sprint(i % 2)}
			}
			es = append(es, logs.Event{Record: event.Record{Kind: kind, View: view, Fields: map[string]any{}}, Input: in.ID, Node: in.Node, Profile: profile, Run: "engine", Line: line, Wall: wall.Add(time.Duration(line) * time.Millisecond).Format(time.RFC3339Nano), Mono: mono})
		}
		ns := func(n int64) *int64 { return &n }
		add(event.RoundEnter, "18446744073709551617", ns(0))
		add(event.PreprepareAccept, "18446744073709551617", ns(int64(i+1)*10000000))
		add(event.NewHead, "18446744073709551617", ns(90000000))
		if i == 1 {
			add(event.RoundEnter, "18446744073709551618", nil)
			add(event.PreprepareAccept, "18446744073709551618", nil)
			add(event.NewHead, "18446744073709551618", nil)
			add(event.RoundEnter, "18446744073709551619", ns(0))
			add(event.EngineStop, "", ns(10000000))
			add(event.PreprepareAccept, "18446744073709551619", ns(20000000))
			add(event.NewHead, "18446744073709551619", ns(30000000))
		} else {
			add(event.RoundEnter, "18446744073709551618", ns(0))
			add(event.NewHead, "18446744073709551618", ns(20000000))
			add(event.RoundEnter, "18446744073709551619", ns(20000000))
			add(event.PreprepareAccept, "18446744073709551619", ns(10000000))
			add(event.NewHead, "18446744073709551619", ns(30000000))
		}
		// A nearby lower-width height must not leak into the full-width interval.
		add(event.RoundEnter, "1", ns(0))
		add(event.PreprepareAccept, "1", ns(999999999))
		if err = s.PutLogEvents(ctx, d.ID, es, int64(len(es))); err != nil {
			t.Fatal(err)
		}
		if i != 4 {
			if err = s.FinishRange(ctx, d.ID, int64(len(es)), ""); err != nil {
				t.Fatal(err)
			}
		}
		release()
		ids = append(ids, d.ID)
		if i == 0 {
			network = d.NetworkID
		}
	}
	c := client{t, (&Server{Store: s}).Handler()}
	path := fmt.Sprintf("/v1/networks/%d/phases/comparison", network)
	query := url.Values{"datasets": {fmt.Sprintf("%d,%d", ids[0], ids[1])}, "from": {"18446744073709551617"}, "to": {"18446744073709551620"}, "metric": {"preprepare"}}
	var out store.PhaseComparison
	if c.do("GET", path+"?"+query.Encode(), nil, &out) != 200 {
		t.Fatal(out)
	}
	if out.Rounds.Expected != 4 || len(out.Runs) != 2 || out.Rounds.Runs[0].Observers[0].Missing != 1 {
		t.Fatal(out)
	}
	for _, run := range out.Runs {
		if len(run.Coverage) != 1 || run.Coverage[0].Observed != 3 || run.Coverage[0].Missing != 1 {
			t.Fatal(run.Coverage)
		}
		for _, g := range run.Summary.Groups {
			if g.Node == "" || g.Profile == "" {
				t.Fatal("pooled observers", g)
			}
		}
	}
	a := out.Runs[0].Summary.Groups[0]
	if a.Clock != "monotonic" || a.Total != 3 || a.Valid != 1 || a.Missing != 1 || a.Negative != 1 || a.P95 == nil || *a.P95 != .01 {
		t.Fatal(a)
	}
	if out.Runs[1].Summary.Samples != 4 || len(out.Runs[1].Summary.Groups) != 2 {
		t.Fatal(out.Runs[1])
	}
	for _, g := range out.Runs[1].Summary.Groups {
		if g.Clock == "monotonic" && (g.Valid != 1 || g.Missing != 2 || g.P50 == nil || *g.P50 != .02) {
			t.Fatal(g)
		}
		if g.Clock == "wall" && (g.Valid != 1 || g.P50 == nil || math.Abs(*g.P50-.001) > 1e-12) {
			t.Fatal(g)
		}
	}
	for _, run := range out.Runs {
		for _, sample := range run.Examples {
			for _, point := range []*latency.Source{sample.Start, sample.End} {
				if point == nil {
					continue
				}
				var original store.LogEvent
				source := fmt.Sprintf("/v1/networks/%d/datasets/%d/events/%s/%d", network, run.Dataset, point.Input, point.Line)
				if c.do("GET", source, nil, &original) != 200 || original.Wall != point.Wall || original.Height != sample.Height {
					t.Fatal("source identity changed", source, point, original)
				}
			}
		}
	}
	cross := url.Values{}
	for k, values := range query {
		cross[k] = append([]string{}, values...)
	}
	cross.Set("cross_network", "1")
	cross.Set("datasets", fmt.Sprintf("%d,%d", ids[0], ids[3]))
	var different store.PhaseComparison
	if c.do("GET", path+"?"+cross.Encode(), nil, &different) != 200 || different.Runs[0].Network.ChainID != "77" || different.Runs[1].Network.ChainID != "77" || different.Runs[0].Network.GenesisHash == different.Runs[1].Network.GenesisHash || len(different.Rounds.Comparisons) != 0 {
		t.Fatal("explicit independent network comparison lost identity", different)
	}
	cross.Set("datasets", fmt.Sprintf("%d,%d", ids[0], ids[2]))
	if c.do("GET", path+"?"+cross.Encode(), nil, nil) != 400 {
		t.Fatal("cross-network opt-in admitted source copies")
	}
	for _, change := range []map[string]string{
		{"datasets": fmt.Sprintf("%d,%d", ids[0], ids[0])}, {"datasets": fmt.Sprintf("%d,%d", ids[0], ids[2])}, {"datasets": fmt.Sprintf("%d,%d", ids[0], ids[3])}, {"datasets": fmt.Sprintf("%d,%d", ids[0], ids[4])}, {"datasets": fmt.Sprintf("%d,99999999", ids[0])}, {"datasets": fmt.Sprint(ids[0])},
		{"from": "01", "to": "1"}, {"cross_network": "true"}, {"cross_network": ""}, {"from": "18446744073709551621"}, {"to": "18446744073709651617"}, {"metric": ""}, {"metric": "bad"}, {"node": "other"}, {"node": "../unsafe"}, {"from_t": "2030-01-01T00:00:00Z"},
	} {
		copy := url.Values{}
		for k, values := range query {
			copy[k] = append([]string{}, values...)
		}
		for k, value := range change {
			copy.Set(k, value)
		}
		if c.do("GET", path+"?"+copy.Encode(), nil, nil) != 400 {
			t.Fatal("invalid comparison accepted", change)
		}
	}
	if c.do("GET", path+"?"+query.Encode()+"&metric=preprepare", nil, nil) != 400 {
		t.Fatal("duplicate parameter accepted")
	}
}

func TestPhaseComparisonTotalContextLimit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ids := []int64{}
	var network int64
	for i, count := range []int{1, 100000} {
		d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: "91", GenesisHash: "0x" + strings.Repeat("2", 64)}, fmt.Sprintf("bounded-phase-%d", i), json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		input := logs.InputSummary{ID: "input", Node: "node", Profile: "wbft@123456789012", ProfileSHA256: strings.Repeat("c", 64), SHA256: strings.Repeat(fmt.Sprint(i), 64)}
		if err = s.PutLogInput(ctx, d.ID, input); err != nil {
			t.Fatal(err)
		}
		for start := 0; start < count; start += 2000 {
			es := []logs.Event{}
			for j := start; j < min(start+2000, count); j++ {
				es = append(es, logs.Event{Record: event.Record{Kind: event.Quorum, View: &event.View{Seq: "1", Round: "0"}, Fields: map[string]any{"what": "PREPARE"}}, Node: input.Node, Input: input.ID, Profile: input.Profile, Run: "engine", Line: int64(j + 1), Wall: "2030-01-01T00:00:00Z"})
			}
			if err = s.PutLogEvents(ctx, d.ID, es, int64(min(start+2000, count))); err != nil {
				t.Fatal(err)
			}
		}
		if err = s.FinishRange(ctx, d.ID, int64(count), ""); err != nil {
			t.Fatal(err)
		}
		release()
		ids = append(ids, d.ID)
		network = d.NetworkID
	}
	c := client{t, (&Server{Store: s}).Handler()}
	path := fmt.Sprintf("/v1/networks/%d/phases/comparison?datasets=%d,%d&from=1&to=1&metric=prepare_quorum", network, ids[0], ids[1])
	if c.do("GET", path, nil, nil) != 400 {
		t.Fatal("total context limit did not include both independent runs")
	}
}

func TestPhaseComparisonExampleBoundPreservesFullStatistics(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ids := []int64{}
	var network int64
	for run, count := range []int{65, 1} {
		d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: "92", GenesisHash: "0x" + strings.Repeat("3", 64)}, fmt.Sprintf("example-phase-%d", run), json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		for i := range count {
			in := logs.InputSummary{ID: fmt.Sprintf("n%02d", i), Node: fmt.Sprintf("n%02d", i), Profile: "wbft@123456789012", ProfileSHA256: strings.Repeat("c", 64), SHA256: fmt.Sprintf("%064x", run*100+i)}
			if err = s.PutLogInput(ctx, d.ID, in); err != nil {
				t.Fatal(err)
			}
			es := []logs.Event{}
			for j, kind := range []event.Kind{event.RoundEnter, event.PreprepareAccept} {
				ns := fmt.Sprint(j * 1000000)
				es = append(es, logs.Event{Record: event.Record{Kind: kind, View: &event.View{Seq: "1", Round: "0"}, Fields: map[string]any{}}, Node: in.Node, Input: in.ID, Profile: in.Profile, Run: "engine", Line: int64(j + 1), Wall: fmt.Sprintf("2030-01-01T00:00:00.%03dZ", j), Mono: &ns})
			}
			if err = s.PutLogEvents(ctx, d.ID, es, int64((i+1)*2)); err != nil {
				t.Fatal(err)
			}
		}
		if err = s.FinishRange(ctx, d.ID, int64(count*2), ""); err != nil {
			t.Fatal(err)
		}
		release()
		ids = append(ids, d.ID)
		network = d.NetworkID
	}
	c := client{t, (&Server{Store: s}).Handler()}
	var result store.PhaseComparison
	path := fmt.Sprintf("/v1/networks/%d/phases/comparison?datasets=%d,%d&from=1&to=1&metric=preprepare", network, ids[0], ids[1])
	if c.do("GET", path, nil, &result) != 200 {
		t.Fatal(result)
	}
	if len(result.Runs[0].Examples) != 64 || !result.Runs[0].ExamplesTruncated || len(result.Runs[0].Summary.Groups) != 65 || result.Runs[0].Summary.Samples != 65 || len(result.Runs[0].Coverage) != 65 {
		t.Fatal("example limit truncated measurements", result.Runs[0])
	}
	if result.Runs[1].ExamplesTruncated {
		t.Fatal("invented evidence truncation")
	}
}

func TestPhaseComparisonRetainsInterveningEngineBoundary(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ids := []int64{}
	var network int64
	for i := range 2 {
		d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: "93", GenesisHash: "0x" + strings.Repeat("4", 64)}, fmt.Sprintf("boundary-phase-%d", i), json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		input := logs.InputSummary{ID: "input", Node: "node", Profile: "wbft@123456789012", ProfileSHA256: strings.Repeat("c", 64), SHA256: strings.Repeat(fmt.Sprint(i), 64)}
		if err = s.PutLogInput(ctx, d.ID, input); err != nil {
			t.Fatal(err)
		}
		es := []logs.Event{}
		for j, kind := range []event.Kind{event.RoundEnter, event.EngineStop, event.PreprepareAccept} {
			if i == 1 && kind == event.EngineStop {
				continue
			}
			run := "core"
			view := &event.View{Seq: "1", Round: "0"}
			if kind == event.EngineStop {
				run = "shutdown-worker"
				view = nil
			}
			mono := fmt.Sprint(j * 1000000)
			es = append(es, logs.Event{Record: event.Record{Kind: kind, View: view, Fields: map[string]any{}}, Node: input.Node, Input: input.ID, Profile: input.Profile, Run: run, Line: int64(j + 1), Wall: fmt.Sprintf("2030-01-01T00:00:00.%03dZ", j), Mono: &mono})
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
	var before latency.Summary
	route := fmt.Sprintf("/v1/networks/%d/datasets/%d/phases/summary?from_t=2030-01-01T00:00:00Z&to_t=2030-01-01T00:00:01Z&metric=preprepare", network, ids[0])
	if c.do("GET", route, nil, &before) != 200 || before.Samples != 2 {
		t.Fatal("original reader lost engine boundary", before)
	}
	var result store.PhaseComparison
	route = fmt.Sprintf("/v1/networks/%d/phases/comparison?datasets=%d,%d&from=1&to=1&metric=preprepare", network, ids[0], ids[1])
	if c.do("GET", route, nil, &result) != 200 {
		t.Fatal(result)
	}
	group := result.Runs[0].Summary.Groups[0]
	if group.Valid != 0 || group.Missing != 2 || group.Total != 2 {
		t.Fatal("height comparison joined across intervening engine stop", group)
	}
}

func TestPhaseComparisonIncludesExplicitDecisionNumberWithoutView(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ids := []int64{}
	var network int64
	for i := range 2 {
		d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: "94", GenesisHash: "0x" + strings.Repeat("5", 64)}, fmt.Sprintf("explicit-number-phase-%d", i), json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		profile, kind := "wbft@123456789012", event.FinalizeHandover
		if i == 1 {
			profile, kind = "gstable@123456789012", event.NewHead
		}
		input := logs.InputSummary{ID: "input", Node: "node", Profile: profile, ProfileSHA256: strings.Repeat("c", 64), SHA256: strings.Repeat(fmt.Sprint(i), 64)}
		if err = s.PutLogInput(ctx, d.ID, input); err != nil {
			t.Fatal(err)
		}
		records := []logs.Event{{Record: event.Record{Kind: kind, Fields: map[string]any{"number": "18446744073709551617", "round": "0"}}, Node: input.Node, Input: input.ID, Profile: input.Profile, Run: "engine", Line: 1, Wall: "2030-01-01T00:00:00Z"}}
		if err = s.PutLogEvents(ctx, d.ID, records, 1); err != nil {
			t.Fatal(err)
		}
		if err = s.FinishRange(ctx, d.ID, 1, ""); err != nil {
			t.Fatal(err)
		}
		release()
		ids = append(ids, d.ID)
		network = d.NetworkID
	}
	c := client{t, (&Server{Store: s}).Handler()}
	var old latency.Summary
	route := fmt.Sprintf("/v1/networks/%d/datasets/%d/phases/summary?from_t=2030-01-01T00:00:00Z&to_t=2030-01-01T00:00:01Z&metric=round_to_decision", network, ids[0])
	if c.do("GET", route, nil, &old) != 200 || old.Samples != 1 {
		t.Fatal("original phase reader lost explicit decision number", old)
	}
	var result store.PhaseComparison
	route = fmt.Sprintf("/v1/networks/%d/phases/comparison?datasets=%d,%d&from=18446744073709551617&to=18446744073709551617&metric=round_to_decision", network, ids[0], ids[1])
	if c.do("GET", route, nil, &result) != 200 {
		t.Fatal(result)
	}
	for _, run := range result.Runs {
		if run.Summary.Samples != 1 || len(run.Examples) != 1 || run.Examples[0].Height != "18446744073709551617" || run.Coverage[0].Observed != 1 || run.Coverage[0].Missing != 0 {
			t.Fatal("height selection lost explicit decision number", run)
		}
		if group := run.Summary.Groups[0]; group.Valid != 0 || group.Missing != 1 || group.P95 != nil {
			t.Fatal("missing start promoted to valid latency", group)
		}
	}
}
