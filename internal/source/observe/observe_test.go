package observe

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	client "github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/0xmhha/wbft/observe/participation"
)

func reply(method string, params []string, value any) Reply {
	raw, _ := json.Marshal(value)
	return Reply{Method: method, Params: params, Response: json.RawMessage(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":%s}`, raw))}
}
func fixture() Archive {
	h := "18446744073709551617"
	node := "0x" + strings.Repeat("1", 40)
	hash := "0x" + strings.Repeat("2", 64)
	records := []participation.Record{{Height: h, Source: "header", Hash: hash, Round: "0", Proposer: node, Rounds: []participation.Round{{Round: "0", Proposer: node, Outcome: "committed"}}, Validators: []participation.ValidatorRound{{Round: "0", Validator: node, Index: 0, InPrevCommitted: true}}}}
	info := map[string]any{"impl": "wbft", "address": node, "validator": true, "chainId": 8, "genesisHash": hash, "head": map[string]string{"number": h, "hash": hash}, "mode": "embedded", "version": "v0.0.0-synthetic", "build": "cgo", "logProfile": "wbft@synthetic", "improvements": []any{}, "ruleActivations": map[string]string{}, "rulesDigest": hash, "unexpected": "secret"}
	return Archive{Format: Format, From: h, To: h, Replies: []Reply{reply("wbft_nodeInfo", []string{}, info), reply("wbft_participation", []string{h, h}, records), reply("wbft_participationSummary", []string{h, h}, participation.Summarize(records)), reply("wbft_configAt", []string{h}, map[string]any{"number": h, "requestTimeoutMs": 2000, "blockPeriodSeconds": 1, "epochLength": 100, "transitions": []any{}}), reply("wbft_headerCopy", []string{hash}, map[string]any{"number": h, "hash": hash, "round": 0, "path": "imported", "preparedSeal": nil, "committedSeal": map[string]any{"sealers": []uint32{0}, "signature": "secret"}})}}
}
func TestFullHeightHeaderOnlyMetadataAndSummary(t *testing.T) {
	a := fixture()
	s, e := Normalize(a)
	if e != nil || s.Comparison.Status != "match" || s.Comparison.Computed.Local != 0 || s.Comparison.Computed.Heights != 1 {
		t.Fatal(s, e)
	}
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), "secret") || !strings.Contains(string(raw), a.From) {
		t.Fatal("payload retained or height truncated", string(raw))
	}
	var cp Copy
	if e = json.Unmarshal(s.Calls[4].Data, &cp); e != nil || cp.Prepared != nil || cp.Committed == nil || len(*cp.Committed) != 1 {
		t.Fatal(cp, e)
	}
	var summary participation.Summary
	_ = json.Unmarshal(s.Calls[2].Data, &summary)
	summary.Gaps = 1
	a.Replies[2] = reply("wbft_participationSummary", a.Replies[2].Params, summary)
	s, e = Normalize(a)
	if e != nil || s.Comparison.Status != "different" || len(s.Comparison.DifferentFields) != 1 || s.Comparison.DifferentFields[0] != "gaps" {
		t.Fatal(s, e)
	}
}
func TestNativeDevelopmentVersionIsRecorded(t *testing.T) {
	a := fixture()
	var env map[string]json.RawMessage
	_ = json.Unmarshal(a.Replies[0].Response, &env)
	var node map[string]any
	_ = json.Unmarshal(env["result"], &node)
	node["version"] = "(devel)"
	a.Replies[0] = reply("wbft_nodeInfo", []string{}, node)
	s, e := Normalize(a)
	if e != nil || s.Node.Version != "(devel)" {
		t.Fatal(s, e)
	}
}

func TestUnavailableNeverBecomesEmptyAndScopesAreStrict(t *testing.T) {
	for _, response := range []string{`{"jsonrpc":"2.0","id":1,"result":null}`, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"secret"}}`} {
		a := fixture()
		a.Replies[1].Response = json.RawMessage(response)
		s, e := Normalize(a)
		if e != nil || s.Comparison.Status != "unavailable" || s.Calls[1].Status != "unavailable" {
			t.Fatal(s, e)
		}
		raw, _ := json.Marshal(s)
		if strings.Contains(string(raw), "secret") {
			t.Fatal(string(raw))
		}
	}
	for _, change := range []func(*Archive){
		func(a *Archive) { a.Replies = append(a.Replies, a.Replies[0]) },
		func(a *Archive) { a.Replies[1].Params[0] = "1" },
		func(a *Archive) {
			a.Replies[1] = reply("wbft_participation", a.Replies[1].Params, []participation.Record{})
		},
		func(a *Archive) {
			a.Replies[1].Response = json.RawMessage(`{"jsonrpc":"2.0","id":1,"id":2,"result":[]}`)
		},
		func(a *Archive) {
			a.Replies[1] = reply("wbft_participation", a.Replies[1].Params, []participation.Record{{Height: a.From, Gap: true, Hash: "0x" + strings.Repeat("2", 64)}})
		},
	} {
		a := fixture()
		change(&a)
		if _, e := Normalize(a); e == nil {
			t.Fatal("invalid observation accepted", a)
		}
	}
	for _, r := range [][2]string{{"0", "1024"}, {"01", "1"}, {"2", "1"}, {"-1", "1"}} {
		if _, _, e := Range(r[0], r[1]); e == nil {
			t.Fatal(r)
		}
	}
}
func TestFetchUsesRecordedHashAndFullHeightRequests(t *testing.T) {
	archive := fixture()
	lookup := map[string]Reply{}
	for _, r := range archive.Replies {
		b, _ := json.Marshal([]any{r.Method, r.Params})
		lookup[string(b)] = r
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []struct {
			ID     int      `json:"id"`
			Method string   `json:"method"`
			Params []string `json:"params"`
		}
		if e := json.NewDecoder(r.Body).Decode(&batch); e != nil {
			t.Error(e)
			w.WriteHeader(400)
			return
		}
		out := []map[string]any{}
		for _, q := range batch {
			requests++
			b, _ := json.Marshal([]any{q.Method, q.Params})
			src, ok := lookup[string(b)]
			if !ok {
				t.Errorf("unexpected request %s", b)
				w.WriteHeader(400)
				return
			}
			var raw map[string]any
			_ = json.Unmarshal(src.Response, &raw)
			raw["id"] = q.ID
			out = append([]map[string]any{raw}, out...)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	c, e := client.New(server.URL, 5)
	if e != nil {
		t.Fatal(e)
	}
	a, e := Fetch(context.Background(), c, archive.From, archive.To)
	if e != nil || requests != 5 {
		t.Fatal(a, e, requests)
	}
	s, e := Normalize(a)
	if e != nil || s.Comparison.Status != "match" {
		t.Fatal(s, e)
	}
}

func TestHeaderOnlyCannotClaimArrivalsAndOverflowIsRefused(t *testing.T) {
	a := fixture()
	var env map[string]json.RawMessage
	_ = json.Unmarshal(a.Replies[1].Response, &env)
	var rows []participation.Record
	_ = json.Unmarshal(env["result"], &rows)
	at := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	delay := int64(1)
	rows[0].Validators[0].Prepare = &participation.Seen{At: at, Via: "direct", Outcome: "ACCEPT", DelayMs: &delay}
	a.Replies[1] = reply("wbft_participation", a.Replies[1].Params, rows)
	if _, e := Normalize(a); e == nil {
		t.Fatal("header-only arrival claim accepted")
	}
	rows[0].Source = "local"
	delay = math.MaxInt64
	second := rows[0]
	second.Height = "18446744073709551618"
	rows = append(rows, second)
	a.To = second.Height
	a.Replies[1] = reply("wbft_participation", []string{a.From, a.To}, rows)
	a.Replies[2].Params = []string{a.From, a.To}
	if _, e := Normalize(a); e == nil || !strings.Contains(e.Error(), "aggregate") {
		t.Fatal("delay overflow accepted", e)
	}
	a = fixture()
	var node map[string]any
	_ = json.Unmarshal(a.Replies[0].Response, &env)
	_ = json.Unmarshal(env["result"], &node)
	delete(node, "validator")
	a.Replies[0] = reply("wbft_nodeInfo", []string{}, node)
	if _, e := Normalize(a); e == nil {
		t.Fatal("missing validator role silently became observer")
	}
}
