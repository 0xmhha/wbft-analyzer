package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestGovernanceHeaderEvidenceIdentityAndLateHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, sourceHash, headerHash, status string
		foreign                              bool
	}{
		{"legacy", "", "", "unknown_hash", false},
		{"missing", "a", "", "header_unavailable", false},
		{"foreign-network", "a", "a", "header_unavailable", true},
		{"different-hash", "a", "b", "hash_mismatch", false},
		{"matched", "a", "a", "matched", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			a, _, err := governance.Load("../source/governance/testdata/capture.json")
			if err != nil {
				t.Fatal(err)
			}
			if tc.sourceHash != "" {
				var envelope map[string]json.RawMessage
				var ops []map[string]json.RawMessage
				if json.Unmarshal(a.Replies[2].Response, &envelope) != nil || json.Unmarshal(envelope["result"], &ops) != nil {
					t.Fatal("fixture")
				}
				ops[0]["blockHash"], _ = json.Marshal("0x" + strings.Repeat(tc.sourceHash, 64))
				envelope["result"], _ = json.Marshal(ops)
				a.Replies[2].Response, _ = json.Marshal(envelope)
			}
			r, err := ingest.Governance(ctx, s, "header-evidence", "archive", strings.Repeat("1", 64), a)
			if err != nil {
				t.Fatal(err)
			}
			original, err := s.GovernanceCall(ctx, r.DatasetID, 3)
			if err != nil {
				t.Fatal(err)
			}
			base := fmt.Sprintf("/v1/networks/%d/datasets/%d/governance/calls/3/entries/1/header-context", r.NetworkID, r.DatasetID)
			handler := (&Server{Store: s}).Handler()
			read := func() map[string]any {
				t.Helper()
				request := httptest.NewRequest("GET", base+"?collection=operations", nil)
				request.Host = "127.0.0.1:8080"
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != 200 {
					t.Fatalf("header context missing: HTTP %d, %s", response.Code, response.Body.String())
				}
				(client{t, handler}).conforms("GET", base+"?collection=operations", response)
				var result map[string]any
				if json.Unmarshal(response.Body.Bytes(), &result) != nil {
					t.Fatal("response")
				}
				return result
			}
			before := read()
			wantBefore := "header_unavailable"
			if tc.sourceHash == "" {
				wantBefore = "unknown_hash"
			}
			if before["header_status"] != wantBefore {
				t.Fatal(before)
			}
			if tc.headerHash != "" {
				identity, err := governance.Normalize(a)
				if err != nil {
					t.Fatal(err)
				}
				key := store.NetworkKey{ChainID: identity.Before.ChainID, GenesisHash: identity.Before.GenesisHash}
				if tc.foreign {
					key.ChainID = "9"
				}
				d, release, err := s.BeginRange(ctx, key, "independent-headers", json.RawMessage(`{}`))
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				f := headers.Fact{Index: "18446744073709551615", Number: "36893488147419103231", Hash: "0x" + strings.Repeat(tc.headerHash, 64), Validators: []string{}, EpochInfo: json.RawMessage(`null`)}
				for i := 0; i < 21; i++ {
					c := headers.Copy{Index: f.Index, Hash: f.Hash, Node: fmt.Sprintf("node-%02d", i)}
					if err := s.PutHeaders(ctx, d.ID, d.NetworkID, []headers.Fact{f}, []headers.Copy{c}, 1); err != nil {
						t.Fatal(err)
					}
				}
				if err := s.FinishRange(ctx, d.ID, 1, ""); err != nil {
					t.Fatal(err)
				}
			}
			got := read()
			if got["header_status"] != tc.status || got["cause_status"] != "unestablished" || got["index"] != "18446744073709551615" || got["source_number"] != "0xffffffffffffffff" || got["normalized_pointer"] != "/data/0" {
				t.Fatal(got)
			}
			if tc.status == "matched" {
				h := got["header"].(map[string]any)
				if h["number"] != "36893488147419103231" || len(got["sources"].([]any)) != 20 || got["sources_truncated"] != true {
					t.Fatal(got)
				}
			} else if got["header"] != nil || len(got["sources"].([]any)) != 0 {
				t.Fatal("unmatched source linked", got)
			}
			after, err := s.GovernanceCall(ctx, r.DatasetID, 3)
			if err != nil {
				t.Fatal(err)
			}
			left, _ := json.Marshal(original)
			right, _ := json.Marshal(after)
			if string(left) != string(right) {
				t.Fatal("header lookup mutated original source")
			}
			c := client{t, handler}
			for _, suffix := range []string{"?collection=faults", "?collection=operations&collection=operations", "?collection=operations&unknown=1", "", "?collection=changes"} {
				if code := c.do("GET", base+suffix, nil, nil); code != 400 {
					t.Fatal(suffix, code)
				}
			}
			for _, path := range []string{strings.Replace(base, "/entries/1/", "/entries/0/", 1), strings.Replace(base, "/entries/1/", "/entries/01/", 1)} {
				if c.do("GET", path+"?collection=operations", nil, nil) != 400 {
					t.Fatal(path)
				}
			}
			if c.do("GET", strings.Replace(base, "/entries/1/", "/entries/2/", 1)+"?collection=operations", nil, nil) != 404 {
				t.Fatal("absent entry accepted")
			}
		})
	}
}

func TestGovernanceHeaderEvidenceChangeEpochAndIndependentNestedHash(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, _, err := governance.Load("../source/governance/testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	var changes []map[string]json.RawMessage
	if json.Unmarshal(a.Replies[4].Response, &envelope) != nil || json.Unmarshal(envelope["result"], &changes) != nil {
		t.Fatal("fixture")
	}
	hash := "0x" + strings.Repeat("a", 64)
	changes[0]["blockHash"], _ = json.Marshal(hash)
	envelope["result"], _ = json.Marshal(changes)
	a.Replies[4].Response, _ = json.Marshal(envelope)
	r, err := ingest.Governance(ctx, s, "epoch-header-context", "archive", strings.Repeat("2", 64), a)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := governance.Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginRange(ctx, store.NetworkKey{ChainID: identity.Before.ChainID, GenesisHash: identity.Before.GenesisHash}, "epoch-source", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	address := "0x" + strings.Repeat("1", 40)
	f := headers.Fact{Index: "18446744073709551615", Number: "36893488147419103231", Hash: hash, Validators: []string{address}, EpochInfo: json.RawMessage(`{"Candidates":[{"Addr":"` + address + `"}],"Validators":[0]}`)}
	copy := headers.Copy{Index: f.Index, Hash: hash, Node: "source"}
	if err := s.PutHeaders(ctx, d.ID, d.NetworkID, []headers.Fact{f}, []headers.Copy{copy}, 1); err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/governance/calls/5/entries/1/header-context", r.NetworkID, r.DatasetID)
	var got store.GovernanceHeaderContext
	if c.do("GET", base+"?collection=changes", nil, &got) != 200 || got.HeaderStatus != "matched" || got.Pointer != "/data/0" || got.Epoch == nil {
		t.Fatal(got)
	}
	if e := got.Epoch; e.Status != "available" || e.Candidates != "matched" || e.Validators != "matched" || e.Added != "matched" || e.Removed != "matched" || e.NoKeyStatus != "unverified_execution_keys" {
		t.Fatal(e)
	}
	if len(got.Sources) != 1 || got.Sources[0].Status != "importing" {
		t.Fatal("copy import status was hidden", got)
	}
	if c.do("GET", base+"?collection=operations", nil, &got) != 200 || got.HeaderStatus != "unknown_hash" || got.SourceBlockHash != nil || got.Header != nil || got.Pointer != "/data/0/ops/0" {
		t.Fatal("parent hash backfilled nested entry", got)
	}
	if c.do("GET", strings.Replace(base, "/calls/5/", "/calls/3/", 1)+"?collection=operations", nil, &got) != 200 || got.HeaderStatus != "unknown_hash" || got.Header != nil {
		t.Fatal("cross-request hash inferred", got)
	}
	if c.do("GET", strings.Replace(base, "/calls/5/", "/calls/99/", 1)+"?collection=changes", nil, nil) != 404 {
		t.Fatal("absent original request accepted")
	}
}
