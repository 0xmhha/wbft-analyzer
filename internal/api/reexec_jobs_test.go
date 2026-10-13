package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestReplayJobsDisabledAndScopedRead(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-jobs", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = s.PutMessageInput(ctx, d.ID, messages.Summary{ID: "journal", Kind: "journal"}); err != nil {
		t.Fatal(err)
	}
	job, err := s.EnqueueReexec(ctx, store.ReexecJob{Dataset: d.ID, Input: "journal", Source: "configured", SourceSHA: strings.Repeat("a", 64), From: "1", To: "2", Mode: "closed"})
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d", d.NetworkID, d.ID)
	var sources ReexecSources
	if c.do("GET", base+"/reexec-sources", nil, &sources) != 200 || sources.Enabled || len(sources.Sources) != 0 {
		t.Fatal(sources)
	}
	if c.do("POST", base+"/reexec-jobs", []byte(`{"source_id":"configured","from_height":"1","to_height":"2"}`), nil) != 503 {
		t.Fatal("disabled worker accepted job")
	}
	var jobs ReexecJobs
	if c.do("GET", base+"/reexec-jobs", nil, &jobs) != 200 || len(jobs.Jobs) != 1 {
		t.Fatal(jobs)
	}
	var got store.ReexecJob
	if c.do("GET", fmt.Sprintf("%s/reexec-jobs/%d", base, job.ID), nil, &got) != 200 || got.Status != "queued" {
		t.Fatal(got)
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/999/datasets/%d/reexec-jobs/%d", d.ID, job.ID), nil, nil) != 404 {
		t.Fatal("cross-network job exposed")
	}
	if c.do("GET", base+"/reexec-jobs?limit=unbounded", nil, nil) != 400 {
		t.Fatal("query accepted")
	}
	if c.do("GET", base+"/reexec-jobs/-1", nil, nil) != 400 {
		t.Fatal("invalid job ID")
	}
}
