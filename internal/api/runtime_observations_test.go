package api

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestRuntimeSourceRetainsExactIdentityAndRejectsConflict(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	capture, e := runtimeobs.Load("../source/runtimeobs/testdata/task-synthetic.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	key := store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("2", 64)}
	out, e := ingest.Runtime(ctx, s, key, "synthetic-runtime", capture)
	if e != nil {
		t.Fatal(e)
	}
	again, e := ingest.Runtime(ctx, s, key, "synthetic-runtime", capture)
	if e != nil || !again.Skipped || again.DatasetID != out.DatasetID {
		t.Fatal(again, e)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/runtime", out.NetworkID, out.DatasetID)
	var summary RuntimeSummary
	if c.do("GET", base, nil, &summary) != 200 || !summary.Complete || summary.RuntimeModelComplete || summary.PointCount != 13 || summary.TaskCount != 1 || summary.Startup == nil || summary.Startup.Line != 1 || summary.Startup.Config == nil || summary.Startup.Config.Height != "18446744073709551616" {
		t.Fatal(summary)
	}
	var page RuntimeCallPage
	if c.do("GET", base+"/calls", nil, &page) != 200 || len(page.Calls) != 1 || page.Calls[0].ID != "18446744073709551615" {
		t.Fatal(page)
	}
	var source RuntimeCallSource
	if c.do("GET", base+"/calls/18446744073709551615", nil, &source) != 200 || source.Start.Line != 2 || source.End.Line != 3 || source.End.Height != "18446744073709551616" || source.SourceSHA != capture.SourceSHA || source.Start.ID != source.End.ID || source.Task == nil || len(source.Task.Stages) != 8 || source.Task.State != "observed_result" || len(source.Task.Intervals) != 3 {
		t.Fatal(source)
	}
	if c.do("GET", base+"/calls/1", nil, nil) != 404 || c.do("GET", base+"/calls?after=-1", nil, nil) != 400 || c.do("GET", base+"/calls?after=2", nil, nil) != 400 || c.do("GET", base+"?private=x", nil, nil) != 400 {
		t.Fatal("invalid source allowed")
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets/%d/runtime", out.NetworkID+1, out.DatasetID), nil, nil) != 404 {
		t.Fatal("foreign network allowed")
	}
	capture.SourceSHA = strings.Repeat("a", 64)
	if _, e = ingest.Runtime(ctx, s, key, "synthetic-runtime", capture); e == nil {
		t.Fatal("content replacement allowed")
	}
	original, e := s.RuntimeCapture(ctx, out.DatasetID)
	if e != nil || original.SourceSHA == capture.SourceSHA {
		t.Fatal("failed replacement corrupted capture", e)
	}
}

func TestRuntimeEngineSourcesUseExactParentsAndPreserveAllStages(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	capture, e := runtimeobs.Load("../source/runtimeobs/testdata/core-synthetic.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	key := store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("2", 64)}
	out, e := ingest.Runtime(ctx, s, key, "synthetic-core", capture)
	if e != nil {
		t.Fatal(e)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/runtime", out.NetworkID, out.DatasetID)
	var summary RuntimeSummary
	if c.do("GET", base, nil, &summary) != 200 || summary.EngineCount != 1 || summary.EngineStates["observed_stopped"] != 1 || summary.RuntimeModelComplete {
		t.Fatal(summary)
	}
	for _, id := range []string{"42", "43"} {
		var source RuntimeCallSource
		if c.do("GET", base+"/calls/"+id, nil, &source) != 200 || len(source.Engines) != 1 {
			t.Fatal(source)
		}
		engine := source.Engines[0]
		if engine.ID != "18446744073709551614" || engine.ParentID != "42" || engine.Created.Line != 3 || engine.Created.ID != engine.ID || len(engine.Stages) != 11 || engine.Stages[10].ParentID != "43" || engine.State != "observed_stopped" {
			t.Fatal(engine)
		}
	}
	var source RuntimeCallSource
	if c.do("GET", base+"/calls/18446744073709551615", nil, &source) != 200 || len(source.Engines) != 0 || source.Task == nil {
		t.Fatal("nearby unrelated call selected", source)
	}
	// Oversized candidate evidence is refused, never truncated into a preferred set.
	capture.Engines[0].Stages = make([]runtimeobs.Point, 257)
	large, e := ingest.Runtime(ctx, s, key, "synthetic-core-large", capture)
	if e != nil {
		t.Fatal(e)
	}
	path := fmt.Sprintf("/v1/networks/%d/datasets/%d/runtime/calls/42", large.NetworkID, large.DatasetID)
	if c.do("GET", path, nil, nil) != 400 {
		t.Fatal("oversized candidate source allowed")
	}
}
