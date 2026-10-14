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

func TestWhatifJobsExposePinnedPolicyAndRespectDatasetScope(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	dataset, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-timer-job-api", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = s.PutMessageInput(ctx, dataset.ID, messages.Summary{ID: "journal", Kind: "journal", Node: "node", SHA256: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	seconds := "2"
	job, err := s.EnqueueWhatif(ctx, store.WhatifJob{Dataset: dataset.ID, Input: "journal", Source: "registered", SourceSHA: strings.Repeat("f", 64), InputSHA: strings.Repeat("a", 64), ChainSHA: strings.Repeat("b", 64), HelperSHA: strings.Repeat("c", 64), Policy: whatif.Policy{Request: &seconds}})
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/whatif-jobs", dataset.NetworkID, dataset.ID)
	var jobs WhatifJobs
	if c.do("GET", base, nil, &jobs) != 200 || len(jobs.Jobs) != 1 || jobs.Jobs[0].PolicySHA != job.PolicySHA {
		t.Fatal(jobs)
	}
	var actual store.WhatifJob
	if c.do("GET", fmt.Sprintf("%s/%d", base, job.ID), nil, &actual) != 200 || actual.HelperSHA != job.HelperSHA || actual.Run != nil {
		t.Fatal(actual)
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/999/datasets/%d/whatif-jobs/%d", dataset.ID, job.ID), nil, nil) != 404 {
		t.Fatal("foreign network job exposed")
	}
	if c.do("POST", fmt.Sprintf("/v1/networks/%d/datasets/%d/whatif", dataset.NetworkID, dataset.ID), []byte(`{"source_id":"registered","timer_policy":{"request_timeout_seconds":"2"}}`), nil) != 503 {
		t.Fatal("unconfigured worker accepted timer work")
	}
}
