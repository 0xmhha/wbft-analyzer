package messages

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
)

const typedSyncTestNode = "0xaa00000000000000000000000000000000000000"

func preparedTypedSync(t *testing.T, files map[string]string) (Prepared, string) {
	t.Helper()
	root := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	in := Input{ID: "typed", Kind: "sync_notifications", Node: typedSyncTestNode, Path: root}
	summary, err := Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return Prepared{Input: in, Summary: summary}, root
}
func readTypedRows(p Prepared) ([]Record, Stats, error) {
	var rows []Record
	stats, err := Read(context.Background(), p, "9", "0x"+strings.Repeat("0", 64), func(r Record) error { rows = append(rows, r); return nil })
	return rows, stats, err
}

func TestTypedSyncProjectionPreservesAbsentSequenceAndSourceClocks(t *testing.T) {
	p, _ := preparedTypedSync(t, map[string]string{"notifications.jsonl": typedSyncFixture(t)})
	rows, stats, err := readTypedRows(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 8 || stats.Records != 8 || stats.ClockRegressions != 1 || stats.ClockDiagnostics != "downloader_posted_sequence" || stats.Frames != 0 || stats.Decoded != 0 || stats.PartialRuns != 0 {
		t.Fatal(rows, stats)
	}
	for i, r := range rows {
		proof := r.NotificationEvidence
		if r.Ordinal != int64(i+1) || r.Input != p.Input.ID || r.File != "notifications.jsonl" || r.Node != typedSyncTestNode || r.Run != "synthetic-sync-notifications" || proof == nil || !proof.RetainedComplete || proof.Header.Ordinal != 1 || proof.Header.Seq != "" || proof.Footer == nil || proof.Footer.Ordinal != 8 || proof.Footer.Seq != "" {
			t.Fatal(r)
		}
		if r.Mono != nil || r.SyncControl != nil || r.SyncEvidence != nil || r.Journal != nil || r.IO != nil || r.Height != "" || r.Round != "" || r.Signer != "" || r.PayloadSHA256 != "" || r.Dir != "" {
			t.Fatal("typed metadata became a protocol/canonical event", r)
		}
	}
	if rows[0].Seq != "" || rows[7].Seq != "" || rows[0].NotificationSource.Stage != "header" || rows[7].NotificationSource.Stage != "footer" {
		t.Fatal("header/footer gained a synthetic source sequence", rows[0], rows[7])
	}
	if rows[1].ClockSource != "downloader_posted" || rows[1].Wall != "2026-01-01T00:00:00.000000123Z" || rows[2].ClockSource != "unavailable" || rows[2].Wall != "" || rows[3].Wall != "2025-12-31T23:59:59Z" {
		t.Fatal("source clock availability/order changed", rows)
	}
	if rows[4].Seq != "4" || rows[4].Notification.Number != "9007199254740993" || rows[6].Notification.Number != "115792089237316195423570985008687907853269984665640564039457584007913129639935" {
		t.Fatal("exact source integers changed")
	}
	if _, _, err := SelectedPayload(context.Background(), p, rows[4], "9", "0x"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("downloader header hash became a protocol payload")
	}
}

func TestTypedSyncPrepareUsesExplicitKindAndDeclaredNetwork(t *testing.T) {
	p, root := preparedTypedSync(t, map[string]string{"notifications.jsonl": typedSyncFixture(t)})
	m := Manifest{Format: Format, Name: "typed-source", Network: logs.Network{ChainID: "9", GenesisHash: "0x" + strings.Repeat("0", 64)}, Clock: Clock{Model: "unknown"}, Inputs: []Input{p.Input}}
	prepared, meta, err := Prepare(context.Background(), m)
	if err != nil || len(prepared) != 1 || prepared[0].Summary.SHA256 != p.Summary.SHA256 {
		t.Fatal(prepared, err)
	}
	var summary struct {
		Normalizer string `json:"normalizer"`
	}
	if json.Unmarshal(meta, &summary) != nil || summary.Normalizer != "wbft-message-normalization/16" {
		t.Fatal(string(meta))
	}
	m.Inputs[0].SHA256 = strings.Repeat("0", 64)
	if _, _, err := Prepare(context.Background(), m); err == nil {
		t.Fatal("wrong prepared checksum accepted")
	}
	if err := os.Symlink(filepath.Join(root, "notifications.jsonl"), filepath.Join(root, "linked.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := Fingerprint(context.Background(), p.Input); err == nil {
		t.Fatal("typed source symlink accepted")
	}
}

func TestTypedSyncIncompleteProjectionHasNoInventedFooterPointer(t *testing.T) {
	raw := typedSyncFixture(t)
	raw = raw[:strings.LastIndex(strings.TrimSuffix(raw, "\n"), "\n")+1]
	p, _ := preparedTypedSync(t, map[string]string{"notifications.jsonl": raw})
	rows, stats, err := readTypedRows(p)
	if err != nil || len(rows) != 7 || stats.PartialRuns != 1 {
		t.Fatal(rows, stats, err)
	}
	for _, r := range rows {
		if r.NotificationEvidence == nil || r.NotificationEvidence.RetainedComplete || r.NotificationEvidence.Footer != nil {
			t.Fatal(r)
		}
	}
}

func TestTypedSyncSourceChangesAndAmbiguityEmitNoPrefix(t *testing.T) {
	for _, name := range []string{"changed-after-prepare", "wrong-node", "duplicate-run", "malformed-second-file", "unsupported-file"} {
		t.Run(name, func(t *testing.T) {
			raw := typedSyncFixture(t)
			files := map[string]string{"a.jsonl": raw}
			if name == "duplicate-run" {
				files["b.jsonl"] = raw
			}
			if name == "malformed-second-file" {
				files["b.jsonl"] = rewriteTypedSyncRow(t, raw, 8, func(r map[string]any) { r["written"] = "5" })
			}
			p, root := preparedTypedSync(t, files)
			if name == "changed-after-prepare" {
				replacement := rewriteTypedSyncRow(t, raw, 1, func(r map[string]any) { r["run"] = "another-run" })
				if err := os.WriteFile(filepath.Join(root, "a.jsonl"), []byte(replacement), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if name == "wrong-node" {
				p.Summary.Node = "0xbb00000000000000000000000000000000000000"
			}
			if name == "unsupported-file" {
				if err := os.WriteFile(filepath.Join(root, "unrecognized.txt"), []byte("NEVER_PERSIST_THIS_TEXT"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rows, _, err := readTypedRows(p)
			if !errors.Is(err, errSyncNotifications) || len(rows) != 0 {
				t.Fatal("unverified typed metadata prefix emitted", rows, err)
			}
		})
	}
}

func TestTypedSyncMultipleRunsRetainOriginalIndependentSequences(t *testing.T) {
	raw := typedSyncFixture(t)
	other := rewriteTypedSyncRow(t, raw, 1, func(r map[string]any) { r["run"] = "another-run" })
	p, _ := preparedTypedSync(t, map[string]string{"a.jsonl": raw, "b.jsonl": other})
	rows, stats, err := readTypedRows(p)
	if err != nil || len(rows) != 16 || stats.Records != 16 {
		t.Fatal(rows, stats, err)
	}
	if rows[1].Seq != "1" || rows[9].Seq != "1" || rows[0].Run == rows[8].Run || rows[8].NotificationEvidence.Header.File != "b.jsonl" || rows[8].NotificationEvidence.Header.Seq != "" {
		t.Fatal("separate source runs were merged or renumbered", rows)
	}
}
