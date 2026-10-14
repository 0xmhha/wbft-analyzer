package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"strings"
	"testing"
)

func TestReexecPagesFollowExecutionAndKeepOriginalPointers(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, e := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-schedule", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	if e = s.PutMessageInput(ctx, d.ID, messages.Summary{ID: "journal", Kind: "journal", Node: "node", SHA256: strings.Repeat("a", 64)}); e != nil {
		t.Fatal(e)
	}
	summary := reexec.Result{Version: reexec.Version, Status: "running", Mode: "counterfactual", AnswerScope: "context", SourceVersions: []string{}, Heights: []reexec.Height{}, Schedule: &reexec.InputSchedule{Action: "swap", Writer: "synthetic", Engine: "1", Step: "1", Other: "2"}}
	id, e := s.BeginReexec(ctx, d.ID, "journal", "1", "1", "private", summary)
	if e != nil {
		t.Fatal(e)
	}
	// Source 20 executes before source 10; both differ, so min(source) is wrong.
	for _, row := range []reexec.Step{{Ordinal: 20, ExecutionOrdinal: 10, Height: "1", Class: "output_diverged", Issues: []string{}}, {Ordinal: 10, ExecutionOrdinal: 20, Height: "1", Class: "output_diverged", Issues: []string{}}} {
		if e = s.PutReexecStep(ctx, id, row); e != nil {
			t.Fatal(e)
		}
	}
	summary.Status = "counterfactual"
	if e = s.FinishReexec(ctx, id, summary); e != nil {
		t.Fatal(e)
	}
	run, e := s.ReexecRun(ctx, d.ID, id)
	if e != nil || run.Summary.FirstMismatch == nil || *run.Summary.FirstMismatch != 20 || run.Summary.FirstMismatchExecution == nil || *run.Summary.FirstMismatchExecution != 10 {
		t.Fatal(run, e)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	path := fmt.Sprintf("/v1/networks/%d/datasets/%d/reexec/%d/steps", d.NetworkID, d.ID, id)
	var page ReexecPage
	if c.do("GET", path+"?limit=1", nil, &page) != 200 || len(page.Steps) != 1 || page.Steps[0].Ordinal != 20 || page.Next == nil || *page.Next != 10 {
		t.Fatal("first execution page", page)
	}
	if c.do("GET", path+"?after=10&limit=1", nil, &page) != 200 || len(page.Steps) != 1 || page.Steps[0].Ordinal != 10 || page.Next != nil {
		t.Fatal("second execution page", page)
	}
}
