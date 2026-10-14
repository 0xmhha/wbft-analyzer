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

func TestWhatifAPIScopeExactCoordinatesAndExecutionPages(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	dataset, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-timer-api", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = s.PutMessageInput(ctx, dataset.ID, messages.Summary{ID: "journal", Kind: "journal", Node: "node", SHA256: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	seconds := "2"
	id, err := s.BeginWhatif(ctx, store.WhatifRun{Dataset: dataset.ID, Input: "journal", SourceSHA: strings.Repeat("a", 64), ChainSHA: strings.Repeat("b", 64), HelperSHA: strings.Repeat("c", 64), Policy: whatif.Policy{Request: &seconds}}, "/private/synthetic-chain")
	if err != nil {
		t.Fatal(err)
	}
	height, round := "9007199254740993", "9007199254740994"
	source := &whatif.Source{Writer: "synthetic", Engine: "18446744073709551615", Step: "1", Ordinal: "3"}
	step := whatif.Step{Execution: "1", Mono: "0", Parent: "0", ArmExecution: "0", Source: source, State: whatif.State{Running: true, Height: &height, Round: &round, Name: "Prepared"}, Input: "start", Digest: "0x" + strings.Repeat("d", 64), Comparable: true, Counterfactual: true, Model: whatif.Model}
	if err = s.PutWhatifStep(ctx, id, step); err != nil {
		t.Fatal(err)
	}
	step.Execution = "2"
	step.Source = nil
	step.Cause = source
	step.Parent = "1"
	step.Generated = true
	step.Comparable = false
	step.Input = "backlog"
	if err = s.PutWhatifStep(ctx, id, step); err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/whatif", dataset.NetworkID, dataset.ID)
	var runs WhatifList
	if c.do("GET", base, nil, &runs) != 200 || len(runs.Runs) != 1 {
		t.Fatal(runs)
	}
	var run store.WhatifRun
	if c.do("GET", fmt.Sprintf("%s/%d", base, id), nil, &run) != 200 {
		t.Fatal(run)
	}
	raw, _ := json.Marshal(run)
	if strings.Contains(string(raw), "synthetic-chain") || strings.Contains(string(raw), "chain_path") {
		t.Fatal("private input path exposed")
	}
	var page WhatifPage
	path := fmt.Sprintf("%s/%d/results", base, id)
	if c.do("GET", path+"?limit=1", nil, &page) != 200 || len(page.Steps) != 1 || page.Next == nil || *page.Next != 1 || *page.Steps[0].State.Height != height {
		t.Fatal(page)
	}
	if c.do("GET", path+"?after=1", nil, &page) != 200 || len(page.Steps) != 1 || page.Steps[0].Source != nil || !page.Steps[0].Generated {
		t.Fatal(page)
	}
	for _, suffix := range []string{"?after=-1", "?limit=1001", "?after=1&after=2", "?source=3"} {
		if c.do("GET", path+suffix, nil, nil) != 400 {
			t.Fatal(suffix)
		}
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/999/datasets/%d/whatif/%d", dataset.ID, id), nil, nil) != 404 {
		t.Fatal("cross-network experiment exposed")
	}
}
