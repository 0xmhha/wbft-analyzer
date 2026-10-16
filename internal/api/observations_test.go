package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/participation"
	native "github.com/0xmhha/wbft/rpc"
)

func TestObservationFullHeightPagingSourceAndForeignScope(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, _, e := observe.Load("../source/observe/testdata/capture.json")
	if e != nil {
		t.Fatal(e)
	}
	a.From, a.To = "18446744073709551617", "18446744073709551618"
	for i, r := range a.Replies {
		var env map[string]json.RawMessage
		_ = json.Unmarshal(r.Response, &env)
		var value any
		switch r.Method {
		case "wbft_nodeInfo":
			var n native.NodeInfo
			_ = json.Unmarshal(env["result"], &n)
			n.Head.Number = a.To
			value = n
		case "wbft_participation":
			var rows []participation.Record
			_ = json.Unmarshal(env["result"], &rows)
			rows[0].Height = a.From
			rows[1].Height = a.To
			value = rows
			a.Replies[i].Params = []string{a.From, a.To}
		case "wbft_participationSummary":
			var summary participation.Summary
			_ = json.Unmarshal(env["result"], &summary)
			summary.From, summary.To = a.From, a.To
			value = summary
			a.Replies[i].Params = []string{a.From, a.To}
		case "wbft_configAt":
			var cfg native.ConfigAtResult
			_ = json.Unmarshal(env["result"], &cfg)
			cfg.Number = a.From
			value = cfg
			a.Replies[i].Params = []string{a.From}
		case "wbft_roundChanges":
			value = []participation.RoundChange{}
			a.Replies[i].Params = []string{a.From, a.To}
		case "wbft_headerCopy":
			var copy native.HeaderCopyResult
			_ = json.Unmarshal(env["result"], &copy)
			copy.Number = a.From
			value = copy
		}
		env["result"], _ = json.Marshal(value)
		a.Replies[i].Response, _ = json.Marshal(env)
	}
	raw, _ := json.Marshal(a)
	sum := sha256.Sum256(raw)
	sha := hex.EncodeToString(sum[:])
	res, e := ingest.Observations(ctx, s, "synthetic-api-observe", "archive", sha, a)
	if e != nil {
		t.Fatal(e)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/observations", res.NetworkID, res.DatasetID)
	var info store.ObservationCapture
	if c.do("GET", base, nil, &info) != 200 || info.Node.HeadNumber != a.To || info.Comparison.Status != "match" {
		t.Fatal(info)
	}
	query := "?from=" + a.From + "&to=" + a.To + "&limit=1"
	var page ObservationPage
	if c.do("GET", base+"/participation"+query, nil, &page) != 200 || page.Total != 2 || len(page.Rows) != 1 || page.Rows[0].Height != a.From || page.Next == nil {
		t.Fatal(page)
	}
	cursor := *page.Next
	if c.do("GET", base+"/participation"+query+"&cursor="+cursor, nil, &page) != 200 || !page.Rows[0].Gap || page.Rows[0].Height != a.To {
		t.Fatal(page)
	}
	if c.do("GET", base+"/participation?from="+a.To+"&to="+a.To+"&cursor="+cursor, nil, nil) != 400 {
		t.Fatal("cross-range cursor accepted")
	}
	var source observe.Call
	if c.do("GET", base+"/calls/5", nil, &source) != 200 || source.Ordinal != 5 || strings.Contains(string(source.Data), "signature") {
		t.Fatal(source)
	}
	for _, q := range []string{"?from=1&to=2", "?from=" + a.From + "&to=" + a.To + "&node=1", "?from=" + a.From + "&to=" + a.To + "&limit=0", "?from=" + a.From + "&to=" + a.To + "&from=1"} {
		if c.do("GET", base+"/participation"+q, nil, nil) == 200 {
			t.Fatal(q)
		}
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets/%d/observations", res.NetworkID+1, res.DatasetID), nil, nil) != 404 {
		t.Fatal("foreign network accepted")
	}
	if c.do("GET", base+"/calls/9999", nil, nil) != 404 {
		t.Fatal("missing call accepted")
	}
}

func TestObservationRoundChangeClaimsAndOriginalAvailability(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name, status string
		result       json.RawMessage
	}{
		{"empty", "match", json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":[]}`)},
		{"different", "different", nil},
		{"unsupported", "unavailable", json.RawMessage(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"secret"}}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, err := observe.Load("../source/observe/testdata/capture.json")
			if err != nil {
				t.Fatal(err)
			}
			kept := a.Replies[:0]
			for _, r := range a.Replies {
				if r.Method != "wbft_roundChanges" {
					kept = append(kept, r)
				}
			}
			a.Replies = kept
			body := tc.result
			if tc.name == "different" {
				body, _ = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": []participation.RoundChange{{Height: a.From, Round: "0", Proposer: "0x1111111111111111111111111111111111111111", Cause: "timeout", Next: "1"}}})
			}
			a.Replies = append(a.Replies, observe.Reply{Method: "wbft_roundChanges", Params: []string{a.From, a.To}, Response: body})
			ordinal := len(a.Replies)
			raw, _ := json.Marshal(a)
			sum := sha256.Sum256(raw)
			result, err := ingest.Observations(ctx, s, "synthetic-round-claims-"+tc.name, "archive", hex.EncodeToString(sum[:]), a)
			if err != nil {
				t.Fatal(err)
			}
			c := client{t, (&Server{Store: s}).Handler()}
			base := fmt.Sprintf("/v1/networks/%d/datasets/%d/observations", result.NetworkID, result.DatasetID)
			var info store.ObservationCapture
			if c.do("GET", base, nil, &info) != 200 || info.RoundChanges == nil || info.RoundChanges.Status != tc.status || info.RoundChanges.ComputedCount == nil || *info.RoundChanges.ComputedCount != 0 {
				t.Fatal(info)
			}
			var call observe.Call
			if c.do("GET", fmt.Sprintf("%s/calls/%d", base, ordinal), nil, &call) != 200 || call.Method != "wbft_roundChanges" || call.Ordinal != int64(ordinal) || call.Params[0] != a.From || call.Params[1] != a.To {
				t.Fatal(call)
			}
			if tc.name == "unsupported" {
				if info.RoundChanges.ReportedCount != nil || call.Status != "unavailable" || call.ErrorCode == nil || *call.ErrorCode != -32601 || string(call.Data) != "null" {
					t.Fatal("unsupported became empty", info, call)
				}
			} else {
				want := 0
				if tc.name == "different" {
					want = 1
				}
				if info.RoundChanges.ReportedCount == nil || *info.RoundChanges.ReportedCount != want || call.Status != "available" {
					t.Fatal(info, call)
				}
				var rows []participation.RoundChange
				if json.Unmarshal(call.Data, &rows) != nil || len(rows) != want {
					t.Fatal("original reported rows changed", call)
				}
			}
			encoded, _ := json.Marshal([]any{info, call})
			if strings.Contains(string(encoded), "secret") {
				t.Fatal("arbitrary error text retained")
			}
		})
	}
}
