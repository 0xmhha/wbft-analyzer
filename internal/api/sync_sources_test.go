package api

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func TestSyncSourceAPIKeepsExactOriginalAndIncompleteContext(t *testing.T) {
	for _, fixture := range []string{"combined", "incomplete"} {
		for _, kind := range []string{"frames", "journal"} {
			t.Run(fixture+"/"+kind, func(t *testing.T) {
				s := testStore(t)
				manifest := messages.Manifest{Format: messages.Format, Name: "sync-" + fixture + "-" + kind, Network: logs.Network{ChainID: "9", GenesisHash: "0x" + strings.Repeat("0", 64)}, Clock: messages.Clock{Model: "unknown"}, Inputs: []messages.Input{{ID: "sync-input", Kind: kind, Node: "0xaa00000000000000000000000000000000000000", Path: "../source/messages/testdata/sync-" + fixture + "/" + kind}}}
				res, err := ingest.Messages(context.Background(), s, manifest)
				if err != nil {
					t.Fatal(err)
				}
				c := client{t, (&Server{Store: s}).Handler()}
				base := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages", res.NetworkID, res.DatasetID)
				var page MessagePage
				if c.do("GET", base+"/records?type=sync_control", nil, &page) != 200 {
					t.Fatal(page)
				}
				want := 5
				if fixture == "incomplete" {
					want = 1
				}
				if len(page.Records) != want {
					t.Fatal("sync filter lost records", page)
				}
				for _, r := range page.Records {
					complete := fixture == "combined"
					if r.SyncControl == nil || r.SyncEvidence == nil || r.SyncEvidence.Complete != complete {
						t.Fatal("source coverage lost", r)
					}
					p := r.SyncEvidence.Declaration
					var declaration messages.Record
					q := url.Values{"input": {p.Input}, "file": {p.File}, "ordinal": {fmt.Sprint(p.Ordinal)}}
					if c.do("GET", base+"/source?"+q.Encode(), nil, &declaration) != 200 || declaration.SyncTrace == nil || declaration.SyncTrace.Complete == nil || *declaration.SyncTrace.Complete != complete || declaration.Mono != nil || declaration.Wall != "" {
						t.Fatal("declaration source changed", declaration)
					}
					if r.SyncControl.Stage != "processed" {
						continue
					}
					if !complete {
						if r.SyncEvidence.Request != nil || r.SyncControl.RequestSource == nil || *r.SyncControl.RequestSource.Available {
							t.Fatal("missing request inferred", r)
						}
						continue
					}
					point := r.SyncEvidence.Request
					if point == nil {
						t.Fatal("exact request missing", r)
					}
					q = url.Values{"input": {point.Input}, "file": {point.File}, "ordinal": {fmt.Sprint(point.Ordinal)}}
					var original messages.Record
					if c.do("GET", base+"/source?"+q.Encode(), nil, &original) != 200 || original.SyncControl == nil || original.SyncControl.Stage != "requested" || original.Node != r.Node || original.Run != r.Run || original.Seq != point.Seq || original.SyncControl.Request != r.SyncControl.Request || original.Journal == nil || original.Journal.Segment != r.SyncControl.RequestSource.Segment || original.Journal.Offset != r.SyncControl.RequestSource.Offset {
						t.Fatal("wrong original request", r, original)
					}
				}
			})
		}
	}
}
