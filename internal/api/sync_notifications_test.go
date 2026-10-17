package api

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func TestTypedSyncAPIOriginalRecordsAndMissingSequence(t *testing.T) {
	raw, err := os.ReadFile("../source/messages/testdata/sync-notifications/complete.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for _, complete := range []bool{true, false} {
		name := "complete"
		if !complete {
			name = "incomplete"
		}
		t.Run(name, func(t *testing.T) {
			data := string(raw)
			if !complete {
				data = data[:strings.LastIndex(strings.TrimSuffix(data, "\n"), "\n")+1]
			}
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "notifications.jsonl"), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			s := testStore(t)
			manifest := messages.Manifest{Format: messages.Format, Name: "typed-sync-" + name, Network: logs.Network{ChainID: "9", GenesisHash: "0x" + strings.Repeat("0", 64)}, Clock: messages.Clock{Model: "unknown"}, Inputs: []messages.Input{{ID: "typed", Kind: "sync_notifications", Node: "0xaa00000000000000000000000000000000000000", Path: root}}}
			result, err := ingest.Messages(context.Background(), s, manifest)
			if err != nil {
				t.Fatal(err)
			}
			c := client{t, (&Server{Store: s}).Handler()}
			base := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages", result.NetworkID, result.DatasetID)
			var inputs MessageInputList
			if c.do("GET", base+"/inputs", nil, &inputs) != 200 || len(inputs.Inputs) != 1 || inputs.Inputs[0].Summary.Kind != "sync_notifications" || inputs.Inputs[0].Stats.Frames != 0 || inputs.Inputs[0].Stats.ClockRegressions != 1 {
				t.Fatal(inputs)
			}
			var page MessagePage
			if c.do("GET", base+"/records?type=sync_notification", nil, &page) != 200 || len(page.Records) != 6 {
				t.Fatal(page)
			}
			for i, r := range page.Records {
				if r.Notification == nil || r.NotificationEvidence == nil || r.NotificationEvidence.RetainedComplete != complete || r.Seq != r.Notification.Sequence || r.Mono != nil || r.Journal != nil {
					t.Fatal(r)
				}
				points := []messages.OwnSourcePoint{r.NotificationEvidence.Header}
				if r.NotificationEvidence.Footer != nil {
					points = append(points, *r.NotificationEvidence.Footer)
				}
				if complete != (r.NotificationEvidence.Footer != nil) {
					t.Fatal("footer source was invented or lost", r)
				}
				for _, p := range points {
					var original messages.Record
					q := url.Values{"input": {p.Input}, "file": {p.File}, "ordinal": {fmt.Sprint(p.Ordinal)}}
					if c.do("GET", base+"/source?"+q.Encode(), nil, &original) != 200 || original.Type != "sync_notification_source" || original.Seq != "" || p.Seq != "" || original.Input != p.Input || original.File != p.File || original.Ordinal != p.Ordinal || original.Node != r.Node || original.Run != r.Run || original.NotificationSource == nil || original.Wall != "" || original.Mono != nil {
						t.Fatal(p, original)
					}
				}
				if i == 1 && (r.Notification.PostedAtAvailable || r.Wall != "" || r.ClockSource != "unavailable") {
					t.Fatal("unavailable clock was repaired", r)
				}
				if i == 3 && r.Notification.Number != "9007199254740993" {
					t.Fatal("number lost precision", r)
				}
			}
			if c.do("GET", base+"/records?type=sync_notification_source", nil, &page) != 200 {
				t.Fatal(page)
			}
			want := 1
			if complete {
				want = 2
			}
			if len(page.Records) != want {
				t.Fatal("source type filter changed", page)
			}
		})
	}
}
