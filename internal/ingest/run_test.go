package ingest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestRunRetryDeduplicationAndUnknownDiagnostics(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "node.log")
	input := `{"t":"2026-10-13T00:00:00.123456789Z","lvl":"info","msg":"WBFT: start new round","next.seq":"18446744073709551617","next.round":"340282366920938463463374607431768211456","payload":"NEVER_STORED"}
{"t":"2026-10-13T00:00:00.123456788Z","lvl":"info","msg":"WBFT: broadcast ROUND-CHANGE message","current.sequence":"18446744073709551617","current.round":"340282366920938463463374607431768211456","data":"NEVER_STORED","payload":"NEVER_STORED"}
{"t":"2026-10-13T00:00:01Z","lvl":"info","msg":"WBFT: unknown NEVER_STORED"}
`
	_ = os.WriteFile(path, []byte(input), 0600)
	m := logs.Manifest{Format: logs.ManifestFormat, Name: "run", Run: "r1", Clock: "unknown", Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Inputs: []logs.File{{ID: "log-1", Node: "n1", Path: path}, {ID: "log-2", Node: "n2", Path: path}}}
	res, err := Run(ctx, s, m, nil)
	if err == nil || res.Events != 4 || len(res.Inputs) != 2 || strings.Contains(err.Error(), "NEVER_STORED") {
		t.Fatal(res, err)
	}
	res2, err := Run(ctx, s, m, nil)
	if err == nil || res2.Events != 4 || res2.DatasetID != res.DatasetID || res2.Skipped {
		t.Fatal(res2, err)
	}
	rows, err := s.LogEvents(ctx, res.DatasetID, store.EventFilter{From: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 13, 0, 0, 2, 0, time.UTC), Limit: 10})
	if err != nil || len(rows) != 4 || rows[0].Height != "18446744073709551617" {
		t.Fatal(rows, err)
	}
	b, _ := json.Marshal(rows)
	if strings.Contains(string(b), "NEVER_STORED") || strings.Contains(string(b), "payload") || strings.Contains(string(b), "data") {
		t.Fatal("unsafe DB event")
	}
	ds, err := s.Datasets(ctx, res.NetworkID)
	if err != nil || ds[0].Status != "failed" || len(ds[0].Nodes) != 2 || !strings.Contains(ds[0].Error, "unknown consensus phrases: 1") {
		t.Fatal(ds, err)
	}
	// The same name cannot silently replace its immutable input.
	_ = os.WriteFile(path, []byte(input+"\n"), 0600)
	if _, err = Run(ctx, s, m, nil); err == nil {
		t.Fatal("changed input overwritten")
	}
	// A clean dataset is complete and repeating it skips its existing rows.
	m.Name = "clean"
	m.Inputs = m.Inputs[:1]
	_ = os.WriteFile(path, []byte(strings.Split(input, "\n")[0]+"\n"), 0600)
	first, err := Run(ctx, s, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(ctx, s, m, nil)
	if err != nil || !second.Skipped || second.Events != 1 || second.DatasetID != first.DatasetID {
		t.Fatal(second, err)
	}
}

func TestActualG7Excerpt(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	m, err := logs.LoadManifest("../source/logs/testdata/g7/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(ctx, s, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	from, _ := time.Parse(time.RFC3339, "2026-10-12T17:22:56Z")
	to, _ := time.Parse(time.RFC3339, "2026-10-12T17:23:30Z")
	summary, err := s.LogRounds(ctx, res.DatasetID, from, to)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, x := range summary.Transitions {
		if x.Round != "0" {
			got[x.Height+":"+x.Round+":"+x.Cause]++
		}
	}
	expected := map[string]int{"5542:1:timeout": 5, "5542:1:f_plus_one": 1, "5565:1:timeout": 5, "5565:2:timeout": 5}
	if len(got) != len(expected) {
		t.Fatal(got)
	}
	for key, count := range expected {
		if got[key] != count {
			t.Fatal(got)
		}
	}
	for _, in := range res.Inputs {
		if in.Stats.Unknown != 0 || in.Stats.Malformed != 0 {
			t.Fatal(in)
		}
	}
	again, err := Run(ctx, s, m, nil)
	if err != nil || !again.Skipped || again.Events != res.Events {
		t.Fatal(again, err)
	}
}
