package api

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func TestCacheSnapshotAPIAndOriginalSource(t *testing.T) {
	s := testStore(t)
	m := messages.Manifest{Format: messages.Format, Name: "cache-source", Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Clock: messages.Clock{Model: "unknown"}, Inputs: []messages.Input{{ID: "cache", Kind: "frames", Node: "0xaa00000000000000000000000000000000000000", Path: "../source/messages/testdata/cache-source-combined"}}}
	res, err := ingest.Messages(context.Background(), s, m)
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages", res.NetworkID, res.DatasetID)
	for typ, count := range map[string]int{"scheduler_trace": 1, "cache_instance": 1, "cache_operation": 2, "frame": 1, "send_suppressed": 1} {
		var page MessagePage
		if c.do("GET", base+"/records?type="+typ, nil, &page) != 200 || len(page.Records) != count {
			t.Fatal(typ, page)
		}
		for _, r := range page.Records {
			if typ == "scheduler_trace" && (r.CacheTrace == nil || r.Scheduler == nil || r.CacheTrace.Complete == nil || !*r.CacheTrace.Complete || r.Mono != nil || r.Wall != "") {
				t.Fatal("shared declaration metadata or unavailable clock lost", r)
			}
			if typ != "frame" && typ != "send_suppressed" {
				continue
			}
			if r.CacheEvidence == nil {
				t.Fatal("exact cache source lost", r)
			}
			for name, p := range map[string]messages.OwnSourcePoint{"declaration": r.CacheEvidence.Declaration, "instance": r.CacheEvidence.Instance, "operation": r.CacheEvidence.Operation} {
				var original messages.Record
				query := fmt.Sprintf("/source?input=%s&file=%s&ordinal=%d", p.Input, p.File, p.Ordinal)
				if c.do("GET", base+query, nil, &original) != 200 || original.Seq != p.Seq || original.Node != r.Node || original.Run != r.Run || original.Ordinal != p.Ordinal {
					t.Fatal("wrong original source", name, p, original)
				}
				if name == "operation" {
					ref := r.CacheDecision
					if r.SendAttempt != nil {
						ref = r.SendAttempt.Decision
					}
					if ref == nil || original.CacheOperation == nil || original.CacheOperation.Instance != ref.Instance || original.CacheOperation.Sequence != ref.Operation || original.Journal == nil || original.Journal.Offset != ref.Offset || original.Journal.Segment != ref.Segment {
						t.Fatal("operation reference lost", r, original)
					}
				}
			}
			if typ == "frame" && (r.SendAttempt == nil || r.SendAttempt.Sequence != "9" || r.CacheEvidence.Operation.Ordinal != 4 || r.Ordinal != 7 || r.Seq != "7") {
				t.Fatal("write aliased to later suppression", r)
			}
			if typ == "send_suppressed" && (r.CacheEvidence.Operation.Ordinal != 5 || r.Mono != nil || r.Wall != "" || r.ClockSource != "unavailable") {
				t.Fatal("suppression context or unknown clock changed", r)
			}
		}
	}
}
