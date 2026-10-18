package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/derive/latency"
	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/event"
)

func activationArchive(t *testing.T, from string) observe.Archive {
	t.Helper()
	a, _, err := observe.Load("../source/observe/testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err = json.Unmarshal(a.Replies[0].Response, &envelope); err != nil {
		t.Fatal(err)
	}
	var node map[string]json.RawMessage
	if err = json.Unmarshal(envelope["result"], &node); err != nil {
		t.Fatal(err)
	}
	node["ruleActivations"], _ = json.Marshal(map[string]string{"example-rule": from})
	envelope["result"], _ = json.Marshal(node)
	a.Replies[0].Response, _ = json.Marshal(envelope)
	return a
}
func activationCapture(t *testing.T, s *store.Store, name, from string) ingest.ObservationResult {
	t.Helper()
	a := activationArchive(t, from)
	raw, _ := json.Marshal(a)
	sum := sha256.Sum256(raw)
	result, err := ingest.Observations(context.Background(), s, name, "archive", hex.EncodeToString(sum[:]), a)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func activationRun(t *testing.T, s *store.Store, network int64, name string, events []logs.Event) store.Dataset {
	t.Helper()
	ctx := context.Background()
	identity, err := s.Network(ctx, network)
	if err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: identity.ChainID, GenesisHash: identity.GenesisHash}, name, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	input := logs.InputSummary{ID: "run-input", Node: "run-observer", Profile: "wbft@123456789012", ProfileSHA256: strings.Repeat("a", 64), SHA256: strings.Repeat("b", 64)}
	if err = s.PutLogInput(ctx, d.ID, input); err != nil {
		t.Fatal(err)
	}
	for i := range events {
		events[i].Input = input.ID
		events[i].Node = input.Node
		events[i].Profile = input.Profile
	}
	if len(events) > 0 {
		if err = s.PutLogEvents(ctx, d.ID, events, int64(len(events))); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.FinishRange(ctx, d.ID, int64(len(events)), ""); err != nil {
		t.Fatal(err)
	}
	return d
}
func activationQuery(capture int64) url.Values {
	return url.Values{"capture": {fmt.Sprint(capture)}, "key": {"example-rule"}, "before": {"2"}, "after": {"2"}, "metric": {"preprepare"}}
}

func TestPhaseActivationBoundarySourceAndIndependentWindows(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	from := "18446744073709551617"
	capture := activationCapture(t, s, "activation-boundary", from)
	activation, _ := new(big.Int).SetString(from, 10)
	events := []logs.Event{}
	add := func(kind event.Kind, height string, round int, mono int64, run string) {
		line := int64(len(events) + 1)
		var view *event.View
		if height != "" {
			view = &event.View{Seq: height, Round: fmt.Sprint(round)}
		}
		value := fmt.Sprint(mono)
		events = append(events, logs.Event{Record: event.Record{Kind: kind, View: view, Fields: map[string]any{}}, Run: run, Line: line, Wall: fmt.Sprintf("2030-01-01T00:00:00.%03dZ", line), Mono: &value})
	}
	for i := -1; i <= 2; i++ {
		height := new(big.Int).Add(activation, big.NewInt(int64(i))).String()
		start := int64(i+1) * 10000000
		add(event.RoundEnter, height, i+1, start, "engine")
		if i == 1 {
			add(event.EngineStop, "", 0, start+1000000, "shutdown-worker")
		}
		add(event.PreprepareAccept, height, i+1, start+int64(i+2)*1000000, "engine")
		add(event.NewHead, height, i+1, start+9000000, "engine")
	}
	run := activationRun(t, s, capture.NetworkID, "activation-run", events)
	c := client{t, (&Server{Store: s}).Handler()}
	route := fmt.Sprintf("/v1/networks/%d/datasets/%d/phases/activation", run.NetworkID, run.ID)
	query := activationQuery(capture.DatasetID)
	var result store.PhaseActivationComparison
	if c.do("GET", route+"?"+query.Encode(), nil, &result) != 200 {
		t.Fatal(result)
	}
	if result.From != from || result.DeclarationCall != 1 || result.Before == nil || result.Before.Rounds.From != "18446744073709551615" || result.Before.Rounds.To != "18446744073709551616" || result.After.Rounds.From != from || result.After.Rounds.To != "18446744073709551618" {
		t.Fatal("activation boundary or full height lost", result)
	}
	var source observe.Call
	original := fmt.Sprintf("/v1/networks/%d/datasets/%d/observations/calls/1", run.NetworkID, capture.DatasetID)
	if c.do("GET", original, nil, &source) != 200 || source.SHA256 != result.Capture.Calls[0].SHA256 || source.Method != "wbft_nodeInfo" {
		t.Fatal("declaration source lost", source)
	}
	if result.Capture.Node.Address == result.After.Runs[0].Coverage[0].Node {
		t.Fatal("invented observer identity")
	}
	before, after := result.Before.Runs[0], result.After.Runs[0]
	if before.Summary.Samples != 1 || before.Summary.Groups[0].Valid != 1 || *before.Summary.Groups[0].P95 != .001 || before.Coverage[0].Observed != 1 || before.Coverage[0].Missing != 1 {
		t.Fatal(before)
	}
	if after.Summary.Samples != 3 || after.Summary.Groups[0].Valid != 1 || after.Summary.Groups[0].Missing != 2 || *after.Summary.Groups[0].P95 != .002 || after.Coverage[0].Observed != 2 || after.Coverage[0].Missing != 0 {
		t.Fatal("boundary or engine stop joined measurements", after)
	}
	if result.Before.Rounds.Runs[0].Observers[0].Known != 1 || result.After.Rounds.Runs[0].Observers[0].Known != 2 || result.Before.Rounds.Runs[0].Observers[0].Bins[0].Round != "0" {
		t.Fatal("round claims pooled", result)
	}
	if !reflect.DeepEqual(before.Summary, independentActivationSummary(t, c, run, []string{"18446744073709551615", "18446744073709551616"})) {
		t.Fatal("before differs from independent reader")
	}
	if !reflect.DeepEqual(after.Summary, independentActivationSummary(t, c, run, []string{from, "18446744073709551618"})) {
		t.Fatal("after differs from independent reader")
	}
	for _, window := range []*store.PhaseComparison{result.Before, &result.After} {
		for _, example := range window.Runs[0].Examples {
			if example.Height < window.Rounds.From || example.Height > window.Rounds.To {
				t.Fatal("example crossed activation", example)
			}
			for _, point := range []*latency.Source{example.Start, example.End} {
				if point == nil {
					continue
				}
				var event store.LogEvent
				path := fmt.Sprintf("/v1/networks/%d/datasets/%d/events/%s/%d", run.NetworkID, run.ID, point.Input, point.Line)
				if c.do("GET", path, nil, &event) != 200 || event.Wall != point.Wall || event.Height != example.Height {
					t.Fatal("source pointer changed", point, event)
				}
			}
		}
	}
	if result.ContextRecords != result.Before.ContextRecords+result.After.ContextRecords {
		t.Fatal("context budget reset")
	}
	if _, err := s.PhaseComparison(ctx, run.NetworkID, []int64{run.ID}, "0", "1", "", "preprepare", false); err == nil {
		t.Fatal("public multi-run comparison admitted a single run")
	}
}

func independentActivationSummary(t *testing.T, c client, run store.Dataset, heights []string) latency.Summary {
	t.Helper()
	samples := []latency.Sample{}
	for _, height := range heights {
		var page PhasePage
		path := fmt.Sprintf("/v1/networks/%d/datasets/%d/phases/samples?from_t=2030-01-01T00:00:00Z&to_t=2030-01-01T00:00:01Z&metric=preprepare&height=%s", run.NetworkID, run.ID, height)
		if c.do("GET", path, nil, &page) != 200 || page.Next != nil {
			t.Fatal("independent samples missing", page)
		}
		samples = append(samples, page.Samples...)
	}
	summary := latency.Summarize(samples)
	groups := []latency.Stats{}
	for _, g := range summary.Groups {
		if g.Node != "" {
			groups = append(groups, g)
		}
	}
	summary.Groups = groups
	summary.Method = "nearest_rank; population standard deviation; separate run/node/profile/clock groups; no overall pooling"
	return summary
}

func TestPhaseActivationZeroAndSelectionRefusals(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	capture := activationCapture(t, s, "activation-zero", "0")
	run := activationRun(t, s, capture.NetworkID, "activation-zero-run", nil)
	c := client{t, (&Server{Store: s}).Handler()}
	route := fmt.Sprintf("/v1/networks/%d/datasets/%d/phases/activation", run.NetworkID, run.ID)
	query := activationQuery(capture.DatasetID)
	var out store.PhaseActivationComparison
	if c.do("GET", route+"?"+query.Encode(), nil, &out) != 200 || out.Before != nil || out.After.Rounds.From != "0" || out.After.Rounds.To != "1" || out.After.Runs[0].Summary.Samples != 0 || out.After.Runs[0].Coverage[0].Missing != 2 {
		t.Fatal("zero activation or absence promoted", out)
	}
	for _, change := range []map[string]string{{"key": "not-reported"}, {"key": ""}, {"capture": fmt.Sprint(run.ID)}, {"capture": "01"}, {"capture": "99999999"}, {"before": "0"}, {"after": "01"}, {"before": "100001"}, {"node": "../unsafe"}, {"node": "absent"}, {"metric": "bad"}, {"unexpected": "1"}} {
		q := activationQuery(capture.DatasetID)
		for k, v := range change {
			q.Set(k, v)
		}
		if c.do("GET", route+"?"+q.Encode(), nil, nil) != 400 {
			t.Fatal("invalid selection admitted", change)
		}
	}
	if c.do("GET", route+"?"+query.Encode()+"&after=2", nil, nil) != 400 {
		t.Fatal("duplicate query admitted")
	}
	for i, variant := range []string{"no-source", "changed-source", "unavailable-source", "duplicate-source", "incomplete"} {
		snap, err := observe.Normalize(activationArchive(t, "0"))
		if err != nil {
			t.Fatal(err)
		}
		switch variant {
		case "no-source":
			snap.Calls = snap.Calls[1:]
		case "changed-source":
			for k := range snap.Node.RuleActivations {
				snap.Node.RuleActivations[k] = "1"
			}
		case "unavailable-source":
			snap.Calls[0].Status = "unavailable"
		case "duplicate-source":
			extra := snap.Calls[0]
			extra.Ordinal = 7
			snap.Calls = append(snap.Calls, extra)
		}
		d, release, e := s.BeginObservations(ctx, store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("1", 64)}, fmt.Sprintf("activation-invalid-%d", i), json.RawMessage(`{}`))
		if e != nil {
			t.Fatal(e)
		}
		if e = s.PutObservation(ctx, d.ID, "archive", strings.Repeat("c", 64), snap); e != nil {
			t.Fatal(e)
		}
		if variant != "incomplete" {
			if e = s.FinishRange(ctx, d.ID, int64(len(snap.Calls)), ""); e != nil {
				t.Fatal(e)
			}
		}
		release()
		q := activationQuery(d.ID)
		if c.do("GET", route+"?"+q.Encode(), nil, nil) != 400 {
			t.Fatal("source mismatch admitted", variant)
		}
	}
	huge := activationCapture(t, s, "activation-overflow", strings.Repeat("9", 156))
	q := activationQuery(huge.DatasetID)
	if c.do("GET", route+"?"+q.Encode(), nil, nil) != 400 {
		t.Fatal("height overflow admitted")
	}
	far := activationCapture(t, s, "activation-range-limit", "100000")
	q = activationQuery(far.DatasetID)
	q.Set("before", "50001")
	q.Set("after", "50000")
	if c.do("GET", route+"?"+q.Encode(), nil, nil) != 400 {
		t.Fatal("combined height limit reset")
	}
	foreign, release, err := s.BeginObservations(ctx, store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("2", 64)}, "activation-foreign", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, foreign.ID, 0, ""); err != nil {
		t.Fatal(err)
	}
	release()
	q = activationQuery(foreign.ID)
	if c.do("GET", route+"?"+q.Encode(), nil, nil) != 400 {
		t.Fatal("foreign genesis admitted")
	}
}

func TestPhaseActivationCombinedContextLimit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	capture := activationCapture(t, s, "activation-budget", "1")
	identity, err := s.Network(ctx, capture.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: identity.ChainID, GenesisHash: identity.GenesisHash}, "activation-budget-run", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	input := logs.InputSummary{ID: "budget", Node: "observer", Profile: "wbft@123456789012", ProfileSHA256: strings.Repeat("d", 64), SHA256: strings.Repeat("e", 64)}
	if err = s.PutLogInput(ctx, d.ID, input); err != nil {
		t.Fatal(err)
	}
	for start := 0; start < 100001; start += 2000 {
		events := []logs.Event{}
		for line := start; line < min(start+2000, 100001); line++ {
			height := "0"
			if line == 100000 {
				height = "1"
			}
			events = append(events, logs.Event{Record: event.Record{Kind: event.Quorum, View: &event.View{Seq: height, Round: "0"}, Fields: map[string]any{"what": "PREPARE"}}, Input: input.ID, Node: input.Node, Profile: input.Profile, Run: "engine", Line: int64(line + 1), Wall: "2030-01-01T00:00:00Z"})
		}
		if err = s.PutLogEvents(ctx, d.ID, events, int64(min(start+2000, 100001))); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.FinishRange(ctx, d.ID, 100001, ""); err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	query := activationQuery(capture.DatasetID)
	query.Set("before", "1")
	query.Set("after", "1")
	query.Set("metric", "prepare_quorum")
	route := fmt.Sprintf("/v1/networks/%d/datasets/%d/phases/activation?%s", d.NetworkID, d.ID, query.Encode())
	if c.do("GET", route, nil, nil) != 400 {
		t.Fatal("before/after reset the combined context budget")
	}
}
