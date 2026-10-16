package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestGovernanceAPIRequestScopesPagingAndSourcePointers(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, sha, err := governance.Load("../source/governance/testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ingest.Governance(ctx, s, "governance-api", "archive", sha, a)
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/governance", r.NetworkID, r.DatasetID)
	var info store.GovernanceCapture
	if c.do("GET", base, nil, &info) != 200 || info.Atomic || info.Before.Head != "18446744073709551616" || info.Operations == nil || *info.Operations != 1 {
		t.Fatal(info)
	}
	for _, item := range []struct {
		call    int
		kind    string
		pointer string
	}{
		{2, "mirrors", "/data"}, {3, "operations", "/data/0"}, {4, "faults", "/data/0"}, {5, "changes", "/data/0"}, {5, "operations", "/data/0/ops/0"}, {6, "states", "/data"}, {7, "proposals", "/data"}, {7, "operations", "/data/ops/0"}, {8, "mirrors", "/data"},
	} {
		var page GovernancePage
		path := fmt.Sprintf("%s/calls/%d/entries?collection=%s&limit=1", base, item.call, item.kind)
		if code := c.do("GET", path, nil, &page); code != 200 || len(page.Rows) != 1 || page.Rows[0].Pointer != item.pointer || page.Rows[0].CallOrdinal != item.call || page.Snapshot != info.Snapshot || page.Call.Ordinal != item.call {
			t.Fatal(path, code, page)
		}
		var source governance.Call
		if c.do("GET", fmt.Sprintf("%s/calls/%d", base, item.call), nil, &source) != 200 || source.SHA256 != page.Call.SHA256 || source.Request.Scope != page.Call.Request.Scope {
			t.Fatal(source)
		}
		if page.Rows[0].Operation != nil {
			var value any
			raw, _ := json.Marshal(source)
			if json.Unmarshal(raw, &value) != nil {
				t.Fatal("source decode")
			}
			for _, key := range strings.Split(strings.TrimPrefix(item.pointer, "/"), "/") {
				switch v := value.(type) {
				case map[string]any:
					value = v[key]
				case []any:
					value = v[0]
				default:
					t.Fatal("invalid source pointer")
				}
			}
			var expected governance.Operation
			raw, _ = json.Marshal(value)
			_ = json.Unmarshal(raw, &expected)
			actual, _ := json.Marshal(page.Rows[0].Operation)
			want, _ := json.Marshal(expected)
			if string(actual) != string(want) {
				t.Fatal("operation source mismatch")
			}
			if item.call == 7 && expected.Number != "0x1" {
				t.Fatal("proposal history truncated")
			}
		}
	}
	var page GovernancePage
	path := base + "/calls/4/entries?collection=faults&limit=1"
	if c.do("GET", path, nil, &page) != 200 || page.Total != 2 || page.Next == nil || !page.Rows[0].Fault.BoundsKnown || *page.Rows[0].Fault.GapFrom != "0x0" {
		t.Fatal(page)
	}
	cursor := *page.Next
	clone, err := ingest.Governance(ctx, s, "governance-api-clone", "archive", sha, a)
	if err != nil {
		t.Fatal(err)
	}
	foreignPage := fmt.Sprintf("/v1/networks/%d/datasets/%d/governance/calls/4/entries?collection=faults&cursor=%s", clone.NetworkID, clone.DatasetID, cursor)
	if c.do("GET", foreignPage, nil, nil) != 400 {
		t.Fatal("cross-dataset cursor accepted")
	}
	if c.do("GET", path+"&cursor="+cursor, nil, &page) != 200 || len(page.Rows) != 1 || page.Rows[0].Ordinal != 2 || page.Rows[0].Fault.BoundsKnown || page.Next != nil {
		t.Fatal(page)
	}
	for _, path := range []string{base + "?unknown=1", base + "/calls/01", base + "/calls/0", base + "/calls/3?unknown=1", base + "/calls/3/entries?collection=operations&cursor=" + cursor, base + "/calls/4/entries?collection=operations", base + "/calls/3/entries?collection=operations&collection=operations", base + "/calls/4/entries?collection=faults&limit=501", base + "/calls/4/entries?collection=faults&cursor=" + strings.Repeat("A", 701), base + "/calls/4/entries?collection=faults&unknown=1"} {
		if code := c.do("GET", path, nil, nil); code != 400 {
			t.Fatal("invalid query accepted", path, code)
		}
	}
	for _, path := range []string{base + "/calls/99", base + "/calls/99/entries?collection=faults", fmt.Sprintf("/v1/networks/%d/datasets/%d/governance", r.NetworkID+1, r.DatasetID)} {
		if code := c.do("GET", path, nil, nil); code != 404 {
			t.Fatal(path, code)
		}
	}
	// A cursor's offset is still bounded even if its scope digest is known.
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		t.Fatal(err)
	}
	var pc phaseCursor
	_ = json.Unmarshal(raw, &pc)
	duplicate := fmt.Sprintf(`{"scope":%q,"scope":%q,"offset":1}`, pc.Scope, pc.Scope)
	if c.do("GET", path+"&cursor="+base64.RawURLEncoding.EncodeToString([]byte(duplicate)), nil, nil) != 400 {
		t.Fatal("duplicate cursor field accepted")
	}
	pc.Offset = 999
	raw, _ = json.Marshal(pc)
	if c.do("GET", path+"&cursor="+base64.RawURLEncoding.EncodeToString(raw), nil, nil) != 400 {
		t.Fatal("unbounded offset accepted")
	}
}

func TestGovernanceAPIUnavailableEmptyAndIncomplete(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, sha, err := governance.Load("../source/governance/testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	for _, status := range []string{"available", "unavailable"} {
		if status == "available" {
			a.Replies[2].Response = json.RawMessage(`{"jsonrpc":"2.0","id":3,"result":[]}`)
		} else {
			a.Replies[2].Response = json.RawMessage(`{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"synthetic-private-error"}}`)
		}
		r, err := ingest.Governance(ctx, s, "governance-"+status, "archive", sha, a)
		if err != nil {
			t.Fatal(err)
		}
		base := fmt.Sprintf("/v1/networks/%d/datasets/%d/governance", r.NetworkID, r.DatasetID)
		var page GovernancePage
		if c.do("GET", base+"/calls/3/entries?collection=operations", nil, &page) != 200 || page.Call.Status != status || page.Total != 0 || len(page.Rows) != 0 || page.Next != nil {
			t.Fatal(page)
		}
		if status == "unavailable" && (page.Call.ErrorCode == nil || *page.Call.ErrorCode != -32601) {
			t.Fatal(page)
		}
		var source governance.Call
		if c.do("GET", base+"/calls/3", nil, &source) != 200 {
			t.Fatal(source)
		}
		raw, _ := json.Marshal(source)
		if strings.Contains(string(raw), "synthetic-private-error") {
			t.Fatal("arbitrary error text exposed")
		}
	}
	snap, err := governance.Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginGovernance(ctx, store.NetworkKey{ChainID: snap.Before.ChainID, GenesisHash: snap.Before.GenesisHash}, "incomplete-governance", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/governance", d.NetworkID, d.ID)
	for _, suffix := range []string{"", "/calls/3", "/calls/3/entries?collection=operations"} {
		if code := c.do("GET", base+suffix, nil, nil); code != 409 {
			t.Fatal(suffix, code)
		}
	}
}
