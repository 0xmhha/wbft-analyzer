package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/participation"
	"github.com/0xmhha/wbft/types"
)

// Only the pre-existing public header samples are read. All native replies
// below are hand-authored synthetic claims, not operational captures.
type followRPC struct {
	mu                   sync.Mutex
	head                 uint64
	gap, outage, foreign bool
	address              string
	headers              map[uint64]*types.Header
	raw                  map[uint64]json.RawMessage
}

func newFollowRPC(t *testing.T) (*followRPC, *rpc.Client) {
	t.Helper()
	f := &followRPC{head: 2, address: "0x" + strings.Repeat("1", 40), headers: map[uint64]*types.Header{}, raw: map[uint64]json.RawMessage{}}
	for i := uint64(0); i <= 4; i++ {
		r, e := os.ReadFile(fmt.Sprintf("../source/headers/testdata/%d.json", i))
		if e != nil {
			t.Fatal(e)
		}
		h, e := headers.DecodeJSON(r)
		if e != nil {
			t.Fatal(e)
		}
		f.headers[i] = h
		f.raw[i] = r
	}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	c, e := rpc.New(server.URL, 5)
	if e != nil {
		t.Fatal(e)
	}
	c.Interval = 0
	return f, c
}
func (f *followRPC) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outage {
		w.WriteHeader(503)
		return
	}
	var requests []struct {
		ID     int
		Method string
		Params []json.RawMessage
	}
	if json.NewDecoder(r.Body).Decode(&requests) != nil {
		w.WriteHeader(400)
		return
	}
	replies := []map[string]any{}
	for _, q := range requests {
		var result any
		arg := func(i int) string { var s string; _ = json.Unmarshal(q.Params[i], &s); return s }
		records := func() []participation.Record {
			a, _ := new(big.Int).SetString(arg(0), 10)
			b, _ := new(big.Int).SetString(arg(1), 10)
			out := []participation.Record{}
			for n := new(big.Int).Set(a); n.Cmp(b) <= 0; n.Add(n, big.NewInt(1)) {
				h := f.headers[n.Uint64()]
				row := participation.Record{Height: n.String(), Gap: true}
				if n.Sign() > 0 && !f.gap && h != nil {
					hash := codec.BlockHash(h).Hex()
					if f.foreign {
						hash = "0x" + strings.Repeat("9", 64)
					}
					row = participation.Record{Height: n.String(), Source: "header", Hash: hash, Round: "0", Proposer: f.address}
				}
				out = append(out, row)
			}
			return out
		}
		switch q.Method {
		case "eth_chainId":
			result = "0x205b"
		case "eth_blockNumber":
			result = "0x" + strconv.FormatUint(f.head, 16)
		case "eth_getBlockByNumber":
			n, _ := strconv.ParseUint(strings.TrimPrefix(arg(0), "0x"), 16, 64)
			result = f.raw[n]
			if f.raw[n] == nil {
				result = json.RawMessage("null")
			}
		case "wbft_nodeInfo":
			result = map[string]any{"impl": "wbft", "address": f.address, "validator": true, "chainId": 8283, "genesisHash": codec.BlockHash(f.headers[0]).Hex(), "head": map[string]string{"number": f.headers[f.head].Number.String(), "hash": codec.BlockHash(f.headers[f.head]).Hex()}, "mode": "embedded", "version": "v0.0.0-synthetic", "build": "synthetic", "logProfile": "wbft@synthetic", "rulesDigest": "0x" + strings.Repeat("4", 64), "improvements": []any{}, "ruleActivations": map[string]string{}}
		case "wbft_participation":
			result = records()
		case "wbft_participationSummary":
			result = participation.Summarize(records())
		case "wbft_configAt":
			result = map[string]any{"number": arg(0), "transitions": []any{}}
		case "wbft_headerCopy":
			result = nil
		default:
			replies = append(replies, map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32601, "message": "synthetic unknown"}})
			continue
		}
		replies = append(replies, map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}
	_ = json.NewEncoder(w).Encode(replies)
}
func followOptions(t *testing.T, c *rpc.Client, name string) FollowOptions {
	t.Helper()
	raw, e := os.ReadFile("../source/headers/testdata/config.json")
	if e != nil {
		t.Fatal(e)
	}
	return FollowOptions{Name: name, Node: name, From: 1, Config: raw, RPC: c}
}

func TestFollowGapOutageAndDurableResume(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	wire, c := newFollowRPC(t)
	o := followOptions(t, c, "synthetic-follow")
	f, e := OpenFollower(ctx, s, o)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	wire.mu.Lock()
	wire.gap = true
	wire.mu.Unlock()
	if _, e = f.Step(ctx); !errors.Is(e, ErrFollowIncomplete) {
		t.Fatal("gap accepted", e)
	}
	cur, e := s.FollowCursor(ctx, f.Dataset.ID)
	if e != nil || cur.Next != "1" {
		t.Fatal("gap advanced", cur, e)
	}
	wire.mu.Lock()
	wire.gap = false
	wire.mu.Unlock()
	r, e := f.Step(ctx)
	if e != nil || r.Next != "2" || r.Headers != 1 {
		t.Fatal(r, e)
	}
	wire.mu.Lock()
	wire.head = 3
	wire.outage = true
	wire.mu.Unlock()
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	_, e = f.Step(short)
	cancel()
	if e == nil {
		t.Fatal("outage accepted")
	}
	cur, e = s.FollowCursor(ctx, f.Dataset.ID)
	if e != nil || cur.Next != "2" {
		t.Fatal("outage advanced", cur, e)
	}
	id := f.Dataset.ID
	f.Close()
	f = nil
	wire.mu.Lock()
	wire.outage = false
	wire.mu.Unlock()
	f, e = OpenFollower(ctx, s, o)
	if e != nil || f.Dataset.ID != id {
		t.Fatal("restart identity", e)
	}
	r, e = f.Step(ctx)
	if e != nil || r.From != 2 || r.Next != "3" {
		t.Fatal("resume skipped or repeated", r, e)
	}
	r, e = f.Step(ctx)
	if e != nil || r.Headers != 0 || r.Next != "3" {
		t.Fatal("caught up cursor", r, e)
	}
	if _, e = OpenFollower(ctx, s, o); e == nil {
		t.Fatal("concurrent follow acquired source")
	}
}

func TestFollowIndependentSourcesAndForeignHash(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, ca := newFollowRPC(t)
	_, cb := newFollowRPC(t)
	fa, e := OpenFollower(ctx, s, followOptions(t, ca, "synthetic-a"))
	if e != nil {
		t.Fatal(e)
	}
	defer fa.Close()
	fb, e := OpenFollower(ctx, s, followOptions(t, cb, "synthetic-b"))
	if e != nil {
		t.Fatal(e)
	}
	defer fb.Close()
	a.mu.Lock()
	a.foreign = true
	a.mu.Unlock()
	if _, e = fa.Step(ctx); !errors.Is(e, ErrFollowIdentity) {
		t.Fatal("foreign participation hash accepted", e)
	}
	if r, e := fb.Step(ctx); e != nil || r.Next != "2" {
		t.Fatal("one source blocked another", r, e)
	}
	cur, e := s.FollowCursor(ctx, fa.Dataset.ID)
	if e != nil || cur.Next != "1" {
		t.Fatal("foreign source advanced", cur, e)
	}
}

func TestFollowCompletenessGate(t *testing.T) {
	for _, s := range []observe.Snapshot{{Comparison: observe.Comparison{Status: "different"}}, {Comparison: observe.Comparison{Status: "match", Computed: &participation.Summary{Gaps: 1}}}, {Comparison: observe.Comparison{Status: "match", Computed: &participation.Summary{}}}} {
		if !errors.Is(completeFollow(s, nil, 1, 1), ErrFollowIncomplete) {
			t.Fatal("incomplete claims accepted")
		}
	}
}
