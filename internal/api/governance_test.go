package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	for _, suffix := range []string{"", "/calls/3", "/calls/3/entries?collection=operations", "/calls/3/entries/1/header-context?collection=operations"} {
		if code := c.do("GET", base+suffix, nil, nil); code != 409 {
			t.Fatal(suffix, code)
		}
	}
}

func TestGovernanceAPIStoredBlockHashesAndLegacyUnknown(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, _, err := governance.Load("../source/governance/testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	hash := "0x" + strings.Repeat("a", 64)
	// Preserve exact JSON numbers while adding independently supplied RPC fields.
	for _, call := range []int{2, 4, 6} {
		var env map[string]json.RawMessage
		if json.Unmarshal(a.Replies[call].Response, &env) != nil {
			t.Fatal("envelope")
		}
		var value any
		dec := json.NewDecoder(strings.NewReader(string(env["result"])))
		dec.UseNumber()
		if dec.Decode(&value) != nil {
			t.Fatal("result")
		}
		if call == 6 {
			for _, op := range value.(map[string]any)["ops"].([]any) {
				op.(map[string]any)["blockHash"] = hash
			}
		} else {
			for _, item := range value.([]any) {
				row := item.(map[string]any)
				row["blockHash"] = hash
				if call == 4 {
					for _, op := range row["ops"].([]any) {
						op.(map[string]any)["blockHash"] = hash
					}
				}
			}
		}
		env["result"], _ = json.Marshal(value)
		a.Replies[call].Response, _ = json.Marshal(env)
	}
	raw, _ := json.Marshal(a)
	sum := sha256.Sum256(raw)
	r, err := ingest.Governance(ctx, s, "governance-with-block-hashes", "archive", hex.EncodeToString(sum[:]), a)
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/governance", r.NetworkID, r.DatasetID)
	var info store.GovernanceCapture
	if c.do("GET", base, nil, &info) != 200 || info.Normalizer != "wbft-governance-normalization/2" {
		t.Fatal(info)
	}
	for _, item := range []struct {
		call       int
		collection string
	}{{3, "operations"}, {5, "changes"}, {5, "operations"}, {7, "operations"}} {
		var page GovernancePage
		path := fmt.Sprintf("%s/calls/%d/entries?collection=%s", base, item.call, item.collection)
		if c.do("GET", path, nil, &page) != 200 || len(page.Rows) != 1 {
			t.Fatal(page)
		}
		row := page.Rows[0]
		var got *string
		if row.Operation != nil {
			got = row.Operation.BlockHash
		} else if row.Change != nil {
			got = row.Change.BlockHash
		}
		if got == nil || *got != hash {
			t.Fatal("typed page lost hash", row)
		}
		var source governance.Call
		if c.do("GET", fmt.Sprintf("%s/calls/%d", base, item.call), nil, &source) != 200 || !strings.Contains(string(source.Data), `"block_hash":"`+hash+`"`) {
			t.Fatal("source lost hash", source)
		}
	}
	legacy, sha, err := governance.Load("../source/governance/testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	lr, err := ingest.Governance(ctx, s, "governance-legacy-hashes", "archive", sha, legacy)
	if err != nil {
		t.Fatal(err)
	}
	var page GovernancePage
	path := fmt.Sprintf("/v1/networks/%d/datasets/%d/governance/calls/3/entries?collection=operations", lr.NetworkID, lr.DatasetID)
	if c.do("GET", path, nil, &page) != 200 || len(page.Rows) != 1 || page.Rows[0].Operation.BlockHash != nil {
		t.Fatal("legacy context invented", page)
	}
}
