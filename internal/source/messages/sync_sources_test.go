package messages

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const syncFixtureNode = "0xaa00000000000000000000000000000000000000"

func readSyncFixture(t *testing.T, path, kind string) ([]Record, Stats, error) {
	t.Helper()
	in := Input{ID: "sync-input", Kind: kind, Node: syncFixtureNode, Path: path}
	summary, err := Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var rows []Record
	stats, err := Read(context.Background(), Prepared{Input: in, Summary: summary}, "9", "0x"+strings.Repeat("0", 64), func(r Record) error { rows = append(rows, r); return nil })
	return rows, stats, err
}

func TestSyncFramesFromCoreExporterPreserveOrderAndOriginalRequest(t *testing.T) {
	// Controlled synthetic journals exported by wbft-journal at 54c2a5417d23.
	// These source links are not consensus verdicts or live network evidence.
	rows, stats, err := readSyncFixture(t, "testdata/sync-combined/frames", "frames")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 6 || len(rows) != 6 {
		t.Fatal("source rows lost", stats, len(rows))
	}
	decl := rows[0]
	if decl.Type != "scheduler_trace" || decl.Scheduler == nil || decl.CacheTrace == nil || decl.SyncTrace == nil || !*decl.SyncTrace.Complete || decl.SyncTrace.Requests != "2" || decl.SyncTrace.Operations != "3" || decl.Wall != "" || decl.Mono != nil {
		t.Fatal("shared source declaration changed", decl)
	}
	for i, ordinal := range map[int]int64{1: 3, 3: 3, 5: 5} {
		r := rows[i]
		if r.Type != "sync_control" || r.SyncControl.Stage != "processed" || r.SyncEvidence == nil || !r.SyncEvidence.Complete || r.SyncEvidence.Request == nil || r.SyncEvidence.Request.Ordinal != ordinal || r.SyncEvidence.Declaration.Ordinal != 1 {
			t.Fatal("exact request source not retained", r)
		}
		source := rows[ordinal-1]
		if r.SyncControl.RequestSource.Seq != source.Seq || r.SyncControl.RequestSource.Segment != source.Journal.Segment || r.SyncControl.RequestSource.Offset != source.Journal.Offset {
			t.Fatal("journal coordinates changed", r, source)
		}
		if r.SyncEvidence.Request.File != source.File || r.SyncEvidence.Request.Input != source.Input || r.SyncEvidence.Request.Seq != source.Seq {
			t.Fatal("original record point changed", r, source)
		}
	}
	if rows[1].SyncControl.EventBefore != "9" || rows[1].SyncControl.EventAfter != "11" || rows[1].Mono == nil || *rows[1].Mono != "4" || rows[2].SyncControl.Stage != "requested" || rows[2].Mono == nil || *rows[2].Mono != "3" {
		t.Fatal("clock or physical source order was rewritten", rows)
	}
	if rows[3].SyncControl.Request != rows[1].SyncControl.Request || rows[3].SyncControl.Operation == rows[1].SyncControl.Operation {
		t.Fatal("repeated request handling was hidden")
	}
}

func TestSyncFramesKeepIncompleteSourceWithoutInventingCoordinates(t *testing.T) {
	rows, stats, err := readSyncFixture(t, "testdata/sync-incomplete/frames", "frames")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 3 || len(rows) != 3 || rows[0].SyncTrace == nil || *rows[0].SyncTrace.Complete || rows[0].SyncTrace.Requests != "0" {
		t.Fatal("incomplete context was hidden", rows, stats)
	}
	c := rows[1]
	if c.SyncEvidence == nil || c.SyncEvidence.Complete || c.SyncEvidence.Request != nil || c.SyncControl.RequestSource == nil || *c.SyncControl.RequestSource.Available || c.SyncControl.RequestSource.Seq != "" || rows[2].Type != "gap" {
		t.Fatal("missing request was inferred", rows)
	}
}

func mutatedSyncFixture(t *testing.T, change func([]map[string]any)) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/sync-combined/frames/frames-sync-control-combined.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	change(rows)
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "frames-sync-control-combined.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(f)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSyncFramesRejectForgedClosedSourceBeforeEmission(t *testing.T) {
	for name, change := range map[string]func([]map[string]any){
		"wrong request coordinate": func(rows []map[string]any) {
			rows[1]["sync_control"].(map[string]any)["request_source"].(map[string]any)["source_offset"] = "999"
		},
		"wrong request state":      func(rows []map[string]any) { rows[2]["sync_control"].(map[string]any)["success"] = true },
		"truncated declared count": func(rows []map[string]any) { rows[0]["sync_trace"].(map[string]any)["operations"] = "4" },
		"missing request identity": func(rows []map[string]any) { rows[2]["sync_control"].(map[string]any)["request"] = "9" },
		"duplicate operation":      func(rows []map[string]any) { rows[3]["sync_control"].(map[string]any)["operation"] = "1" },
		"unknown control payload":  func(rows []map[string]any) { rows[1]["payload"] = strings.Repeat("discard-me", 30) },
		"null required flag":       func(rows []map[string]any) { rows[1]["sync_control"].(map[string]any)["events_available"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			rows, _, err := readSyncFixture(t, mutatedSyncFixture(t, change), "frames")
			if err == nil || len(rows) != 0 {
				t.Fatal("forged source emitted metadata", len(rows), err)
			}
		})
	}
}

func TestSyncFrameDeclarationCanShareCacheWithoutScheduler(t *testing.T) {
	dir := mutatedSyncFixture(t, func(rows []map[string]any) { delete(rows[0], "scheduler_trace"); rows[0]["type"] = "cache_trace" })
	rows, _, err := readSyncFixture(t, dir, "frames")
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Type != "cache_trace" || rows[0].CacheTrace == nil || rows[0].SyncTrace == nil || !*rows[0].SyncTrace.Complete {
		t.Fatal("shared declaration lost", rows[0])
	}
}

func TestSyncJournalAndActualExportKeepTheSameControlMetadata(t *testing.T) {
	for _, name := range []string{"combined", "incomplete"} {
		t.Run(name, func(t *testing.T) {
			base := filepath.Join("testdata", "sync-"+name)
			raw, stats, err := readSyncFixture(t, filepath.Join(base, "journal"), "journal")
			if err != nil {
				t.Fatal(err)
			}
			frames, _, err := readSyncFixture(t, filepath.Join(base, "frames"), "frames")
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != len(frames) || stats.Records != int64(len(frames)) {
				t.Fatal("source record count changed", len(raw), len(frames), stats)
			}
			for i, r := range raw {
				if r.Seq != frames[i].Seq {
					t.Fatal("original journal sequence changed", r, frames[i])
				}
				before, err := json.Marshal(r.SyncControl)
				if err != nil {
					t.Fatal(err)
				}
				after, err := json.Marshal(frames[i].SyncControl)
				if err != nil || string(before) != string(after) {
					t.Fatal("raw control or request coordinates differ from actual export", i, string(before), string(after), err)
				}
				if r.SyncControl != nil {
					if r.SyncEvidence == nil || r.SyncEvidence.Complete != (name == "combined") || r.Mono == nil || frames[i].Mono == nil || *r.Mono != *frames[i].Mono || r.Wall != frames[i].Wall {
						t.Fatal("control source/clock changed", r, frames[i])
					}
					if point := r.SyncEvidence.Request; point != nil {
						if !strings.HasSuffix(point.File, ".wal") || point.File == frames[i].SyncEvidence.Request.File || point.Ordinal != frames[i].SyncEvidence.Request.Ordinal {
							t.Fatal("original raw source replaced with export position", point)
						}
					}
				}
			}
			if raw[0].SyncTrace == nil || *raw[0].SyncTrace.Complete != (name == "combined") || raw[0].SyncTrace.Requests != frames[0].SyncTrace.Requests || raw[0].SyncTrace.Operations != frames[0].SyncTrace.Operations || raw[0].Wall != "" || raw[0].Mono != nil {
				t.Fatal("raw closed trace changed", raw[0])
			}
		})
	}
}
