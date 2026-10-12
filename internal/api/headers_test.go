package api

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestHeaderAPI(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../source/headers/testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ingest.Range(ctx, s, ingest.RangeOptions{Name: "sample", Node: "a", From: 1, To: 3, Config: raw, Source: &headers.Source{Blocks: "../source/headers/testdata"}})
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s, Reporter: &ingest.Reporter{Store: s}}).Handler()}
	var bounds store.HeaderBounds
	if c.do("GET", "/v1/networks/1/header-bounds", nil, &bounds) != 200 || bounds.Count != 4 {
		t.Fatal(bounds)
	}
	var list HeaderList
	if c.do("GET", "/v1/networks/1/headers?from=1&to=3&dataset=1&node=a", nil, &list) != 200 || len(list.Headers) != 3 || list.Headers[0].Copy.Node != "a" {
		t.Fatal(list)
	}
	var ds DatasetList
	if c.do("GET", "/v1/networks/1/datasets", nil, &ds) != 200 || ds.Datasets[0].Status != "complete" || ds.Datasets[0].Progress != 3 {
		t.Fatal(ds)
	}
	var summary store.HeaderSummary
	if c.do("GET", "/v1/networks/1/headers/summary?from=1&to=3", nil, &summary) != 200 || summary.Heights != 3 || summary.UnknownRound != 0 {
		t.Fatal(summary)
	}
	var epochs EpochList
	if c.do("GET", "/v1/networks/1/epochs?from=0&to=3", nil, &epochs) != 200 || len(epochs.Epochs) != 0 {
		t.Fatal(epochs)
	}
	for _, path := range []string{"/v1/networks/1/headers?from=1&to=1025", "/v1/networks/1/headers?from=18446744073709551616&to=18446744073709551617", "/v1/networks/1/headers?from=1&to=3&dataset=1", "/v1/networks/1/headers?from=3&to=1", "/v1/networks/1/headers/summary?from=0&to=100000"} {
		if c.do("GET", path, nil, nil) != 400 {
			t.Fatal(path)
		}
	}
	if c.do("GET", "/v1/networks/1/headers?from=1&to=3&dataset=999&node=a", nil, nil) != 404 {
		t.Fatal("cross-network dataset accepted")
	}
	// Admission preserves only the typed evidence pointer; arbitrary value and
	// payload fields never reach PostgreSQL or its API.
	reportRaw := report(t, func(m map[string]any) {
		m["run"].(map[string]any)["network"] = map[string]any{"chain_id": "8283", "genesis_hash": "0x2bdf79b3d3cc49f9e6638ff81f3bb85065c79945a8fe4556cd0ff47bbfc02490"}
		m["observations"] = []any{map[string]any{"id": "o1", "kind": "late_seal", "imp": []any{}, "count": 1, "requirements": []any{}, "evidence": []any{map[string]any{"kind": "block", "number": "3", "field": "extra.prev_committed_seal", "value": "DO_NOT_STORE", "payload": "DO_NOT_STORE"}}}}
	})
	var loaded LoadResult
	if c.do("POST", "/v1/reports", reportRaw, &loaded) != 201 {
		t.Fatal(loaded)
	}
	var obs ObservationList
	if c.do("GET", "/v1/reports/"+loaded.ID+"/observations", nil, &obs) != 200 || len(obs.Observations[0].Evidence) != 1 || obs.Observations[0].Evidence[0].Number != "3" {
		t.Fatal(obs)
	}
	got, _ := json.Marshal(obs)
	if strings.Contains(string(got), "DO_NOT_STORE") {
		t.Fatal("source values persisted")
	}
}
