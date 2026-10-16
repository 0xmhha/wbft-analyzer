package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestEpochGovernanceExactSourcesAndEntry(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	c := client{t, (&Server{Store: s}).Handler()}
	hash := "0x" + strings.Repeat("a", 64)
	makeCapture := func(name, blockHash string, foreign bool) ingest.GovernanceResult {
		t.Helper()
		a, _, err := governance.Load("../source/governance/testdata/capture.json")
		if err != nil {
			t.Fatal(err)
		}
		for i, r := range a.Replies {
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(r.Response, &envelope); err != nil {
				t.Fatal(err)
			}
			if r.Method == "wbft_validatorChanges" {
				var changes []map[string]json.RawMessage
				if err := json.Unmarshal(envelope["result"], &changes); err != nil {
					t.Fatal(err)
				}
				if blockHash != "" {
					changes[0]["blockHash"], _ = json.Marshal(blockHash)
				}
				envelope["result"], _ = json.Marshal(changes)
			}
			if foreign && r.Method == "wbft_nodeInfo" {
				var info map[string]json.RawMessage
				if err := json.Unmarshal(envelope["result"], &info); err != nil {
					t.Fatal(err)
				}
				info["chainId"] = json.RawMessage(`7`)
				envelope["result"], _ = json.Marshal(info)
			}
			a.Replies[i].Response, _ = json.Marshal(envelope)
		}
		got, err := ingest.Governance(ctx, s, name, "archive", strings.Repeat("1", 64), a)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	matched := makeCapture("matched-source", hash, false)
	makeCapture("unknown-hash", "", false)
	makeCapture("different-fork", "0x"+strings.Repeat("b", 64), false)
	makeCapture("foreign-network", hash, true)
	unfinished := makeCapture("unfinished-source", hash, false)
	if err := s.FinishRange(ctx, unfinished.DatasetID, 0, "fixture import incomplete"); err != nil {
		t.Fatal(err)
	}

	info, err := s.GovernanceCapture(ctx, matched.DatasetID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := s.GovernanceCall(ctx, matched.DatasetID, 5)
	if err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/v1/networks/%d/headers/18446744073709551615/governance", matched.NetworkID)
	if c.do("GET", base, nil, nil) != 404 {
		t.Fatal("header absence hidden")
	}
	d, release, err := s.BeginRange(ctx, store.NetworkKey{ChainID: info.Before.ChainID, GenesisHash: info.Before.GenesisHash}, "epoch-headers", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	addr := "0x" + strings.Repeat("1", 40)
	fact := headers.Fact{Index: "18446744073709551615", Number: "36893488147419103231", Hash: hash, Validators: []string{addr}, EpochInfo: json.RawMessage(`{"Candidates":[{"Addr":"` + addr + `"}],"Validators":[0]}`)}
	if err := s.PutHeaders(ctx, d.ID, d.NetworkID, []headers.Fact{fact}, []headers.Copy{{Index: fact.Index, Hash: hash, Node: "source"}}, 1); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if c.do("GET", base, nil, &got) != 200 {
		t.Fatal("header source link endpoint missing")
	}
	if got["index"] != fact.Index || got["number"] != fact.Number || got["hash"] != hash || got["cause_status"] != "unestablished" || got["truncated"] != false {
		t.Fatal(got)
	}
	rows := got["claims"].([]any)
	if len(rows) != 1 {
		t.Fatal("nonmatching claims promoted", got)
	}
	row := rows[0].(map[string]any)
	if row["dataset_id"] != float64(matched.DatasetID) || row["call_ordinal"] != float64(5) || row["entry_ordinal"] != float64(1) || row["normalized_pointer"] != "/data/0" || row["snapshot"] != info.Snapshot {
		t.Fatal(row)
	}
	entryURL := fmt.Sprintf("/v1/networks/%d/datasets/%d/governance/calls/5/entries/1?collection=changes", matched.NetworkID, matched.DatasetID)
	var entry map[string]any
	if c.do("GET", entryURL, nil, &entry) != 200 || entry["snapshot"] != info.Snapshot {
		t.Fatal(entry)
	}
	selected := entry["entry"].(map[string]any)
	if selected["ordinal"] != float64(1) || selected["normalized_pointer"] != "/data/0" {
		t.Fatal(entry)
	}
	for _, suffix := range []string{"?x=1", "?limit=100", "?index=1"} {
		if c.do("GET", base+suffix, nil, nil) != 400 {
			t.Fatal(suffix)
		}
	}
	for _, index := range []string{"01", "-1", "18446744073709551616"} {
		if c.do("GET", strings.Replace(base, fact.Index, index, 1), nil, nil) != 400 {
			t.Fatal(index)
		}
	}
	for _, query := range []string{"", "?collection=changes&collection=changes", "?collection=faults", "?collection=changes&x=1"} {
		if c.do("GET", strings.Split(entryURL, "?")[0]+query, nil, nil) != 400 {
			t.Fatal(query)
		}
	}
	if c.do("GET", strings.Replace(entryURL, "/entries/1?", "/entries/2?", 1), nil, nil) != 404 {
		t.Fatal("absent row substituted")
	}
	if c.do("GET", strings.Replace(entryURL, "/entries/1?", "/entries/01?", 1), nil, nil) != 400 {
		t.Fatal("noncanonical ordinal")
	}
	for i := 0; i < 20; i++ {
		makeCapture(fmt.Sprintf("another-source-%02d", i), hash, false)
	}
	if c.do("GET", base, nil, &got) != 200 || len(got["claims"].([]any)) != 20 || got["truncated"] != true {
		t.Fatal("source bound missing", got)
	}
	after, err := s.GovernanceCall(ctx, matched.DatasetID, 5)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := json.Marshal(original)
	right, _ := json.Marshal(after)
	if string(left) != string(right) {
		t.Fatal("source mutated")
	}
	if _, err := s.DeleteDataset(ctx, matched.NetworkID, matched.DatasetID, "matched-source"); err != nil {
		t.Fatal(err)
	}
	if c.do("GET", entryURL, nil, nil) != 404 {
		t.Fatal("deleted capture row retained")
	}
	if c.do("GET", base, nil, &got) != 200 || len(got["claims"].([]any)) != 20 || got["truncated"] != false {
		t.Fatal("deleted capture linkage retained", got)
	}
}

func TestGovernanceSingleEntryBeyondFirstPage(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, _, err := governance.Load("../source/governance/testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	a.From = fmt.Sprintf("0x%x", uint64(math.MaxUint64)-1023)
	for i := range a.Replies {
		r := &a.Replies[i]
		if r.Method == "wbft_govOps" || r.Method == "wbft_mirrorFaults" || r.Method == "wbft_validatorChanges" {
			r.Params[0] = a.From
		}
		if r.Method != "wbft_validatorChanges" {
			continue
		}
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(r.Response, &envelope); err != nil {
			t.Fatal(err)
		}
		changes := []map[string]any{}
		for n := uint64(0); n < 501; n++ {
			changes = append(changes, map[string]any{"number": fmt.Sprintf("0x%x", uint64(math.MaxUint64)-500+n), "ops": []any{}, "validators": []any{}})
		}
		envelope["result"], _ = json.Marshal(changes)
		r.Response, _ = json.Marshal(envelope)
	}
	got, err := ingest.Governance(ctx, s, "many-change-rows", "archive", strings.Repeat("1", 64), a)
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/governance/calls/5/entries", got.NetworkID, got.DatasetID)
	var first GovernancePage
	if c.do("GET", base+"?collection=changes", nil, &first) != 200 || len(first.Rows) != 100 || first.Total != 501 {
		t.Fatal(first)
	}
	var row map[string]any
	if c.do("GET", base+"/501?collection=changes", nil, &row) != 200 {
		t.Fatal(row)
	}
	entry := row["entry"].(map[string]any)
	change := entry["change"].(map[string]any)
	if entry["ordinal"] != float64(501) || entry["normalized_pointer"] != "/data/500" || change["number"] != "0xffffffffffffffff" {
		t.Fatal(entry)
	}
	if c.do("GET", base+"/502?collection=changes", nil, nil) != 404 {
		t.Fatal("absent row replaced")
	}
}
