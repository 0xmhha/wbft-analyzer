package replayjob

import (
	"context"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"os"
	"path/filepath"
	"testing"
)

func TestSubmitRejectsScopeBeforeEnqueue(t *testing.T) {
	w := &Worker{sources: map[string]source{"registered": {info: SourceInfo{ID: "registered", Input: "journal", Modes: []string{"closed"}}, network: 1, dataset: 2}}}
	w.running.Store(true)
	tooDeep, negative := 10001, -1
	valid := Request{Source: "registered", From: "1", To: "2", Mode: "closed"}
	for _, r := range []Request{
		{Source: "registered", From: "1", To: "2", Mode: "closed", AnswerScope: "context"},
		{Source: "registered", From: "1", To: "2", Mode: "closed", AnswerScope: "unbounded"},
		{Source: "registered", From: "1", To: "2", Mode: "closed", WarmupHeights: &negative},
		{Source: "registered", From: "1", To: "2", Mode: "closed", WarmupHeights: &tooDeep},
		{Source: "registered", From: "01", To: "2", Mode: "closed"},
		{Source: "registered", From: "0", To: "2", Mode: "closed"},
		{Source: "registered", From: "2", To: "1", Mode: "closed"},
		{Source: "registered", From: "1", To: "10001", Mode: "closed"},
		{Source: "registered", From: "1", To: "18446744073709551616", Mode: "closed"},
		{Source: "registered", From: "1", To: "2", Mode: "counterfactual"},
	} {
		if _, err := w.Submit(context.Background(), 1, 2, r); !errors.Is(err, ErrScope) {
			t.Fatal(r, err)
		}
	}
	if _, err := w.Submit(context.Background(), 9, 2, valid); !errors.Is(err, ErrSource) {
		t.Fatal("cross-network source", err)
	}
	valid.Source = "/private/input"
	if _, err := w.Submit(context.Background(), 1, 2, valid); !errors.Is(err, ErrSource) {
		t.Fatal("path accepted as source", err)
	}
	w.running.Store(false)
	if _, err := w.Submit(context.Background(), 1, 2, valid); !errors.Is(err, ErrSource) {
		t.Fatal("stopped worker", err)
	}
}

func TestLoadRefusesPublicOrUnboundedConfiguration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sources.json")
	for _, raw := range []string{`[]`, `[{"id":"one","unknown":"field"}]`, `[] {}`, string(make([]byte, 65537))} {
		if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(context.Background(), nil, p, "helper"); !errors.Is(err, ErrSource) {
			t.Fatal("invalid configuration accepted", err)
		}
	}
	if err := os.WriteFile(p, []byte(`[{"id":"one","dataset":1,"input":"journal","chain":"chain"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), nil, p, "helper"); !errors.Is(err, ErrSource) {
		t.Fatal("public configuration accepted", err)
	}
}

func TestInputExperimentRequiresExplicitOperatorPolicy(t *testing.T) {
	w := &Worker{sources: map[string]source{"registered": {info: SourceInfo{ID: "registered", Modes: []string{"closed", "counterfactual"}, AnswerScopes: []string{"step", "context"}}, network: 1, dataset: 2}}}
	w.running.Store(true)
	zero := 0
	r := Request{Source: "registered", From: "1", To: "2", Mode: "closed", AnswerScope: "context", WarmupHeights: &zero, Schedule: &reexec.InputSchedule{Action: "drop", Writer: "synthetic", Engine: "1", Step: "2"}}
	if _, e := w.Submit(context.Background(), 1, 2, r); !errors.Is(e, ErrScope) {
		t.Fatal("operator policy bypassed", e)
	}
	src := w.sources["registered"]
	src.info.AllowSchedule = true
	w.sources["registered"] = src
	for _, bad := range []Request{func() Request { x := r; x.WarmupHeights = nil; return x }(), func() Request { x := r; x.AnswerScope = "step"; return x }(), func() Request { x := r; x.Mode = "counterfactual"; return x }()} {
		if _, e := w.Submit(context.Background(), 1, 2, bad); !errors.Is(e, ErrScope) {
			t.Fatal("conflicting experiment policy accepted", e)
		}
	}
}
