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
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestEventPaginationIsSourceAndFilterBound(t *testing.T) {
	s := testStore(t)
	path := filepath.Join(t.TempDir(), "n.log")
	raw := `{"t":"2026-10-13T00:00:00.123456789Z","lvl":"info","msg":"WBFT: start new round","next.seq":"18446744073709551617","next.round":"340282366920938463463374607431768211456"}
{"t":"2026-10-13T00:00:00.123456790Z","lvl":"info","msg":"WBFT: broadcast COMMIT message","current.sequence":"18446744073709551617","current.round":"340282366920938463463374607431768211456"}
{"t":"2026-10-13T00:00:00.123456791Z","lvl":"info","msg":"WBFT: broadcast PREPARE message","current.sequence":"18446744073709551617","current.round":"340282366920938463463374607431768211456"}
`
	_ = os.WriteFile(path, []byte(raw), 0600)
	m := logs.Manifest{Format: logs.ManifestFormat, Name: "run", Run: "run", Clock: "unknown", Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Inputs: []logs.File{{ID: "log-1", Node: "n1", Path: path}, {ID: "log-2", Node: "n2", Path: path}}}
	res, err := ingest.Run(context.Background(), s, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d", res.NetworkID, res.DatasetID)
	var inputs LogInputList
	if c.do("GET", base+"/inputs", nil, &inputs) != 200 || len(inputs.Inputs) != 2 || len(inputs.Inputs[0].ProfileSHA256) != 64 {
		t.Fatal(inputs)
	}
	var detail store.LogEvent
	if c.do("GET", base+"/events/log-1/2", nil, &detail) != 200 || detail.Input != "log-1" || detail.Line != 2 || detail.Kind != "SEND" {
		t.Fatal(detail)
	}
	if c.do("GET", base+"/events/log-3/2", nil, nil) != 404 {
		t.Fatal("cross-source event exposed")
	}
	var bounds store.EventBounds
	if c.do("GET", base+"/event-bounds", nil, &bounds) != 200 || bounds.Count != 6 {
		t.Fatal(bounds)
	}
	q := "?from_t=2026-10-13T00:00:00Z&to_t=2026-10-13T00:00:01Z&limit=1"
	ids := map[string]bool{}
	cursor := ""
	for i := 0; i < 6; i++ {
		var page LogEventPage
		u := base + "/events" + q
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		if c.do("GET", u, nil, &page) != 200 || len(page.Events) != 1 {
			t.Fatal(page)
		}
		e := page.Events[0]
		id := fmt.Sprintf("%s:%d", e.Input, e.Line)
		if ids[id] {
			t.Fatal("cursor repeated nanosecond timestamp row", id)
		}
		ids[id] = true
		if e.Height != "18446744073709551617" || e.Round != "340282366920938463463374607431768211456" {
			t.Fatal(e)
		}
		if i == 5 {
			if page.Next != nil {
				t.Fatal("cursor after end")
			}
		} else {
			if page.Next == nil {
				t.Fatal("missing cursor")
			}
			cursor = *page.Next
		}
	}
	for _, suffix := range []string{"&node=n2", "&phase=COMMIT", "&height=1", "&from_t=2026-10-13T00:00:00.1Z"} {
		if c.do("GET", base+"/events"+q+suffix+"&cursor="+url.QueryEscape(cursor), nil, nil) != 400 {
			t.Fatal("cursor reused across filters", suffix)
		}
	}
	var page LogEventPage
	if c.do("GET", base+"/events"+q+"&node=n2&phase=COMMIT&height=18446744073709551617", nil, &page) != 200 || len(page.Events) != 1 || page.Events[0].Node != "n2" {
		t.Fatal(page)
	}
	for _, bad := range []string{"&limit=1001", "&height=-1", "&height=1e10", "&round=" + strings.Repeat("9", 157), "&phase=VOTE", "&kind=PRIVATE", "&cursor=x"} {
		if c.do("GET", base+"/events"+q+bad, nil, nil) != 400 {
			t.Fatal("invalid filter accepted", bad)
		}
	}
	if c.do("GET", strings.Replace(base, "/networks/1/", "/networks/999/", 1)+"/inputs", nil, nil) != 404 {
		t.Fatal("cross-network dataset exposed")
	}
}
