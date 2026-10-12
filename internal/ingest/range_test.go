package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/rpc"
)

// The two RPC surfaces replay actual public headers independently. Node copies
// use distinct node keys, while the canonical tables contain one chain.
func TestRangeRPCAndResume(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../source/headers/testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requests []struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		replies := []map[string]any{}
		for _, q := range requests {
			var result json.RawMessage
			switch q.Method {
			case "eth_chainId":
				result = json.RawMessage(`"0x205b"`)
			case "eth_getBlockByNumber":
				var n string
				_ = json.Unmarshal(q.Params[0], &n)
				num, _ := strconv.ParseUint(n[2:], 16, 64)
				var err error
				result, err = os.ReadFile(fmt.Sprintf("../source/headers/testdata/%d.json", num))
				if err != nil {
					result = json.RawMessage("null")
				}
			default:
				replies = append(replies, map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32601, "message": "unknown"}})
				continue
			}
			replies = append(replies, map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
		}
		_ = json.NewEncoder(w).Encode(replies)
	})
	for _, node := range []string{"a", "b", "a"} {
		server := httptest.NewServer(handler)
		c, _ := rpc.New(server.URL, 5)
		c.Interval = 0
		result, err := Range(ctx, s, RangeOptions{Name: "public-blocks", Node: node, From: 1, To: 3, Config: raw, Source: &headers.Source{RPC: c}})
		server.Close()
		if err != nil || result.Headers != 3 {
			t.Fatal(result, err)
		}
		bounds, err := s.HeaderBounds(ctx, result.NetworkID)
		if err != nil || bounds.Count != 4 {
			t.Fatal(bounds, err)
		}
		id := result.DatasetID
		rows, err := s.HeaderRows(ctx, result.NetworkID, "1", "3", &id, node)
		if err != nil || len(rows) != 3 || rows[0].Copy == nil {
			t.Fatal(rows, err)
		}
	}
	// A missing source header leaves a failed dataset and never claims completion.
	result, err := Range(ctx, s, RangeOptions{Name: "missing-child", Node: "x", From: 1, To: 5, Config: raw, Source: &headers.Source{Blocks: "../source/headers/testdata"}})
	if err == nil {
		t.Fatal("missing child accepted")
	}
	ds, err := s.Datasets(ctx, result.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	if ds[len(ds)-1].Status != "failed" {
		t.Fatal(ds)
	}
}
