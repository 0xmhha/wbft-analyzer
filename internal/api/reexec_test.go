package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestReexecSourceScopePagesAndFinalisation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-reexec", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = s.PutMessageInput(ctx, d.ID, messages.Summary{ID: "journal", Kind: "journal", Node: "node", SHA256: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	result := reexec.Result{Version: reexec.Version, Status: "running", HelperVersion: "unknown", BinaryVersion: "unknown", VersionStatus: "unknown", SourceVersions: []string{}, Heights: []reexec.Height{}}
	id, err := s.BeginReexec(ctx, d.ID, "journal", "1", "2", "/private/synthetic-chain-object", result)
	if err != nil {
		t.Fatal(err)
	}
	for i, class := range []string{"match", "output_diverged", "not_comparable"} {
		step := reexec.Step{Ordinal: int64(i + 1), File: "00000000000000000000.wal", Run: "synthetic", Engine: "18446744073709551615", Number: fmt.Sprint(i + 1), Height: "1", Input: "message", Recorded: "0x" + strings.Repeat("a", 64), Class: class, Completeness: "complete", Issues: []string{}}
		if err = s.PutReexecStep(ctx, id, step); err != nil {
			t.Fatal(err)
		}
	}
	result.Status = "partial"
	result.Total = 999
	if err = s.FinishReexec(ctx, id, result); err != nil {
		t.Fatal(err)
	}
	row, err := s.ReexecRun(ctx, d.ID, id)
	if err != nil || row.Summary.Total != 3 || row.Summary.Mismatches != 1 || row.Summary.NotComparable != 1 || row.Summary.FirstMismatch == nil || *row.Summary.FirstMismatch != 2 {
		t.Fatal(row, err)
	}
	if err = s.PutReexecStep(ctx, id, reexec.Step{Ordinal: 4, Height: "1", Class: "match"}); !errors.Is(err, store.ErrReexecFinished) {
		t.Fatal("finalised run mutated", err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/reexec", d.NetworkID, d.ID)
	var list ReexecList
	if c.do("GET", base, nil, &list) != 200 || len(list.Runs) != 1 {
		t.Fatal(list)
	}
	var got store.ReexecRun
	if c.do("GET", fmt.Sprintf("%s/%d", base, id), nil, &got) != 200 || got.Summary.FirstMismatch == nil {
		t.Fatal(got)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "synthetic-chain-object") || strings.Contains(string(raw), "chain_path") || strings.Contains(string(raw), `"payload"`) {
		t.Fatal("private replay inputs exposed")
	}
	var page ReexecPage
	path := fmt.Sprintf("%s/%d/steps", base, id)
	if c.do("GET", path+"?limit=1", nil, &page) != 200 || len(page.Steps) != 1 || page.Next == nil || *page.Next != 1 || page.Steps[0].Engine != "18446744073709551615" {
		t.Fatal(page)
	}
	if c.do("GET", path+"?after=1&class=output_diverged", nil, &page) != 200 || len(page.Steps) != 1 || page.Steps[0].Ordinal != 2 || page.Next != nil {
		t.Fatal(page)
	}
	for _, suffix := range []string{"?after=-1", "?limit=1001", "?class=unsupported", "?after=1&after=2", "?height=NaN", "?class=match%7Coutput_diverged", "?after%7Climit=1"} {
		if c.do("GET", path+suffix, nil, nil) != 400 {
			t.Fatal(suffix)
		}
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/999/datasets/%d/reexec/%d", d.ID, id), nil, nil) != 404 {
		t.Fatal("cross-network run exposed")
	}
}
