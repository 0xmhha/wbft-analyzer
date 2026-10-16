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

func TestSchedulerSnapshotIngestFiltersAndOriginalSource(t *testing.T) {
	s := testStore(t)
	m := messages.Manifest{Format: messages.Format, Name: "scheduler-source", Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Clock: messages.Clock{Model: "unknown"}, Inputs: []messages.Input{{ID: "scheduler", Kind: "frames", Node: "0xaa00000000000000000000000000000000000000", Path: "../source/messages/testdata/scheduler-source"}}}
	res, err := ingest.Messages(context.Background(), s, m)
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages", res.NetworkID, res.DatasetID)
	for typ, count := range map[string]int{"scheduler_trace": 1, "scheduler_step": 4, "timer_operation": 8} {
		var p MessagePage
		if c.do("GET", base+"/records?type="+typ, nil, &p) != 200 || len(p.Records) != count {
			t.Fatal(typ, p)
		}
		for _, r := range p.Records {
			if r.Journal == nil {
				t.Fatal("raw position missing", r)
			}
			if typ == "scheduler_trace" && (r.Scheduler == nil || r.Scheduler.Operations != "8" || r.Scheduler.Steps != "4" || r.Mono != nil || r.Wall != "") {
				t.Fatal("declaration fabricated a measured clock", r)
			}
			if typ == "scheduler_step" && (r.EntryMono == nil || r.EntryWall == "") {
				t.Fatal("measured entry missing", r)
			}
		}
	}
	var r messages.Record
	if c.do("GET", base+"/source?input=scheduler&file=frames-scheduler-fixture.jsonl&ordinal=1", nil, &r) != 200 || r.Seq != "1" || r.Scheduler == nil || r.Journal == nil || r.Journal.Offset != "0" || r.ClockSource != "unavailable" {
		t.Fatal("original declaration pointer lost", r)
	}
}
