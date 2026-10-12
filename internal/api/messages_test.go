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

func TestMessageCursorSourceFiltersAndNetwork(t *testing.T) {
	s := testStore(t)
	dir := t.TempDir()
	node := "0x0000000000000000000000000000000000000001"
	var b strings.Builder
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(&b, `{"v":1,"type":"frame","node":%q,"run":"synthetic","seq":%d,"t_wall":"2020-01-01T00:00:00.000000001Z","t_mono_ns":1,"dir":"in","code":"0x13","size":0,"payload":"NEVER_STORED"}`+"\n", node, i)
	}
	if e := os.WriteFile(filepath.Join(dir, "frames-synthetic.jsonl"), []byte(b.String()), 0600); e != nil {
		t.Fatal(e)
	}
	m := messages.Manifest{Format: messages.Format, Name: "messages", Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Clock: messages.Clock{Model: "unknown"}, Inputs: []messages.Input{{ID: "frames", Kind: "frames", Node: node, Path: dir}}}
	res, e := ingest.Messages(context.Background(), s, m)
	if e != nil {
		t.Fatal(e)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages", res.NetworkID, res.DatasetID)
	var inputs MessageInputList
	if c.do("GET", base+"/inputs", nil, &inputs) != 200 || len(inputs.Inputs) != 1 || inputs.Inputs[0].Stats.UnknownPeers != 3 {
		t.Fatal(inputs)
	}
	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 3; i++ {
		var p MessagePage
		u := base + "/records?limit=1"
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		if c.do("GET", u, nil, &p) != 200 || len(p.Records) != 1 {
			t.Fatal(p)
		}
		r := p.Records[0]
		if seen[r.Seq] || r.Ordinal != int64(i+1) || r.Decode != "missing_payload" {
			t.Fatal(r)
		}
		seen[r.Seq] = true
		if i < 2 {
			if p.Next == nil {
				t.Fatal(p)
			}
			cursor = *p.Next
		} else if p.Next != nil {
			t.Fatal(p)
		}
	}
	for _, q := range []string{"&node=" + node, "&type=frame", "&input=frames", "&height=1", "&round=0", "&phase=PREPARE"} {
		if c.do("GET", base+"/records?limit=1"+q+"&cursor="+url.QueryEscape(cursor), nil, nil) != 400 {
			t.Fatal("cross-filter cursor accepted", q)
		}
	}
	for _, q := range []string{"?limit=1001", "?type=bad", "?phase=bad", "?height=-1", "?input=../file", "?cursor=x", "?limit=1&limit=2", "?payload=x"} {
		if c.do("GET", base+"/records"+q, nil, nil) != 400 {
			t.Fatal("invalid filter accepted", q)
		}
	}
	other := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages/inputs", res.NetworkID+1, res.DatasetID)
	if c.do("GET", other, nil, nil) != 404 {
		t.Fatal("foreign network accepted")
	}
}
