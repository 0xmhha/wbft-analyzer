package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/event"
)

func TestLogEvidenceAPI(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	k := store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}
	d, release, err := s.BeginRun(ctx, k, "run", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	hash := strings.Repeat("a", 64)
	in := logs.InputSummary{ID: "log-1", Node: "n1", Profile: "gstable@740526d03", ProfileSHA256: strings.Repeat("b", 64), SHA256: hash, Bytes: 100}
	if err = s.PutLogInput(ctx, d.ID, in); err != nil {
		t.Fatal(err)
	}
	e := logs.Event{Record: event.Record{Kind: event.RoundEnter, View: &event.View{Seq: "1", Round: "2"}, Fields: map[string]any{}}, Node: "n1", Input: "log-1", Run: "r", Wall: "2026-10-13T00:00:00Z", Line: 5, Profile: in.Profile}
	if err = s.PutLogEvents(ctx, d.ID, []logs.Event{e}, 1); err != nil {
		t.Fatal(err)
	}
	// The public report loader must persist only identity from its input metadata.
	raw := report(t, func(m map[string]any) {
		run := m["run"].(map[string]any)
		run["network"] = map[string]any{"chain_id": "7", "genesis_hash": k.GenesisHash}
		run["inputs"] = []any{map[string]any{"id": "report-log", "kind": "log", "node": "n1", "sha256": hash, "profile": in.Profile, "path": "DO_NOT_STORE_PRIVATE_PATH"}}
		m["observations"] = []any{map[string]any{"id": "o1", "kind": "round_change_timeout", "count": 1, "imp": []any{}, "evidence": []any{map[string]any{"kind": "log", "input": "report-log", "node": "n1", "line": 5, "number": "1"}}}}
	})
	var loaded LoadResult
	// Reporter is needed for POST.
	c := client{t, (&Server{Store: s, Reporter: &ingest.Reporter{Store: s}}).Handler()}
	if c.do("POST", "/v1/reports", raw, &loaded) != 201 {
		t.Fatal(loaded)
	}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/evidence", d.NetworkID, d.ID)
	q := "?report=" + loaded.ID + "&observation=o1&index=0"
	var out store.LogEvidence
	if c.do("GET", base+q, nil, &out) != 200 || out.Status != "matched" || out.Event.Line != 5 || out.DatasetInput != "log-1" {
		t.Fatal(out)
	}
	for _, suffix := range []string{"&index=-1", "&index=20", "&index=x"} {
		if c.do("GET", base+q+suffix, nil, nil) != 400 {
			t.Fatal("invalid evidence index accepted")
		}
	}
	if c.do("GET", base+"?report="+loaded.ID+"&observation=missing&index=0", nil, nil) != 404 {
		t.Fatal("unknown observation returned")
	}
	inputs, err := s.ReportInputs(ctx, loaded.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(inputs)
	if strings.Contains(string(b), "DO_NOT_STORE") {
		t.Fatal("copied input path")
	}
	ds, err := s.Datasets(ctx, d.NetworkID)
	if err != nil || len(ds[0].CopyNodes) != 0 || len(ds[0].Nodes) != 1 {
		t.Fatal(ds, err)
	}
}
