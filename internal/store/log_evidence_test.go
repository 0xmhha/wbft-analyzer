package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/reports"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

func TestEvidenceMustMatchNetworkHashNodeAndLine(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key := NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64), Name: "test"}
	d, release, err := s.BeginRun(ctx, key, "run", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	hash := strings.Repeat("a", 64)
	in := logs.InputSummary{ID: "dataset-log", Node: "n1", Profile: "gstable@740526d03", ProfileSHA256: strings.Repeat("c", 64), SHA256: hash, Bytes: 123}
	if err = s.PutLogInput(ctx, d.ID, in); err != nil {
		t.Fatal(err)
	}
	ev := logs.Event{Record: event.Record{Kind: event.RoundEnter, View: &event.View{Seq: "18446744073709551617", Round: "1"}, Fields: map[string]any{}}, Node: "n1", Input: in.ID, Run: "r", Wall: "2026-10-13T00:00:00Z", Profile: in.Profile, Level: "info", Line: 42}
	if err = s.PutLogEvents(ctx, d.ID, []logs.Event{ev}, 1); err != nil {
		t.Fatal(err)
	}
	makeReport := func(id string, k NetworkKey, input ReportInput, p reports.Evidence) {
		r := report(id)
		r.NetworkKey = &k
		r.Inputs = []ReportInput{input}
		b, _ := json.Marshal([]reports.Evidence{p})
		r.Observations = []Observation{{ID: "o1", Kind: "round_change_timeout", Count: 1, Evidence: b}}
		if _, _, err := s.PutReport(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	rin := ReportInput{ID: "report-log", Kind: "log", Node: "n1", SHA256: hash, Profile: in.Profile}
	pointer := reports.Evidence{Kind: "log", Input: rin.ID, Node: "n1", Line: 42, Number: ev.Record.View.Seq}
	makeReport(strings.Repeat("1", 64), key, rin, pointer)
	got, err := s.ResolveLogEvidence(ctx, d.ID, strings.Repeat("1", 64), "o1", 0)
	if err != nil || got.Status != "matched" || got.Event.Line != 42 || got.DatasetInput != in.ID || got.ReportInput != rin.ID || got.Event.Height != pointer.Number {
		t.Fatal(got, err)
	}
	for i, change := range []func(*NetworkKey, *ReportInput, *reports.Evidence){
		func(k *NetworkKey, _ *ReportInput, _ *reports.Evidence) {
			k.GenesisHash = "0x" + strings.Repeat("f", 64)
		},
		func(_ *NetworkKey, in *ReportInput, _ *reports.Evidence) { in.SHA256 = strings.Repeat("b", 64) },
		func(_ *NetworkKey, in *ReportInput, _ *reports.Evidence) { in.Node = "n2" },
		func(_ *NetworkKey, _ *ReportInput, p *reports.Evidence) { p.Line = 43 },
		func(_ *NetworkKey, _ *ReportInput, p *reports.Evidence) { p.Number = "2" },
	} {
		k, r, p := key, rin, pointer
		change(&k, &r, &p)
		id := strings.Repeat(string(rune('2'+i)), 64)
		makeReport(id, k, r, p)
		got, err := s.ResolveLogEvidence(ctx, d.ID, id, "o1", 0)
		if err != nil || got.Status == "matched" || got.Event != nil {
			t.Fatal("unrelated source linked", got, err)
		}
	}
	// Two equal hashes with the same node are ambiguous, never guessed.
	in.ID = "duplicate-log"
	if err = s.PutLogInput(ctx, d.ID, in); err != nil {
		t.Fatal(err)
	}
	got, err = s.ResolveLogEvidence(ctx, d.ID, strings.Repeat("1", 64), "o1", 0)
	if err != nil || got.Status != "ambiguous_source" {
		t.Fatal(got, err)
	}
}

func TestRepeatReportBackfillsIdentityWithoutDuplicatingRows(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	r := report(strings.Repeat("a", 64))
	if _, _, err := s.PutReport(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Inputs = []ReportInput{{ID: "log-1", Kind: "log", Node: "n1", SHA256: strings.Repeat("b", 64)}}
	added, _, err := s.PutReport(ctx, r)
	if err != nil || added {
		t.Fatal(added, err)
	}
	inputs, err := s.ReportInputs(ctx, r.ID)
	if err != nil || len(inputs) != 1 {
		t.Fatal(inputs, err)
	}
	results, observations, err := s.ReportCounts(ctx, r.ID)
	if err != nil || results != 2 || observations != 1 {
		t.Fatal(results, observations, err)
	}
	r.Inputs[0].SHA256 = strings.Repeat("c", 64)
	if _, _, err = s.PutReport(ctx, r); err == nil {
		t.Fatal("changed source identity overwritten")
	}
}
