package messages

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func syntheticSyncJournal(t *testing.T, mode string) string {
	t.Helper()
	dir := t.TempDir()
	id := journal.Identity{Self: types.Address{0xaa}, Run: "controlled-sync", ChainID: big.NewInt(9), Core: journal.CoreOptions{SyncTrace: 1}}
	if mode == "missing-capability" {
		id.Core.SyncTrace = 0
	}
	if mode == "future-capability" {
		id.Core.SyncTrace = 2
	}
	w, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "changing-capability":
		changed := id
		changed.Core.SyncTrace = 0
		w.Put(journal.Record{Body: &journal.SegmentRec{Identity: changed}})
	case "reappearing-writer":
		other := id
		other.Run = "another-controlled-writer"
		w.Put(journal.Record{Body: &journal.SegmentRec{Identity: other}})
		w.Put(journal.Record{Body: &journal.SegmentRec{Identity: id}})
	case "missing-request-prefix":
		w.Put(journal.Record{Body: &journal.SyncRec{Stage: "requested", Request: 2, Syncing: true}})
		w.Put(journal.Record{Body: &journal.SyncRec{Stage: "processed", Request: 2, Operation: 1, Syncing: true, Action: "stop", RunningBefore: true, EventsAvailable: true, EventBefore: 9, EventAfter: 10}})
	case "exhausted-identity":
		w.Put(journal.Record{Body: &journal.SyncRec{Stage: "requested", Syncing: true, SequenceExhausted: true}})
		w.Put(journal.Record{Body: &journal.SyncRec{Stage: "processed", Syncing: true, Action: "none", SequenceExhausted: true}})
	default:
		w.Put(journal.Record{Body: &journal.SyncRec{Stage: "requested", Request: 1, Syncing: true}})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSyncJournalRejectsUnsupportedOrChangingIdentityBeforeEmission(t *testing.T) {
	for _, mode := range []string{"missing-capability", "future-capability", "changing-capability", "reappearing-writer"} {
		t.Run(mode, func(t *testing.T) {
			rows, _, err := readSyncFixture(t, syntheticSyncJournal(t, mode), "journal")
			if err == nil || len(rows) != 0 {
				t.Fatal("ambiguous source emitted metadata", len(rows), err)
			}
		})
	}
}

func TestSyncJournalKeepsMissingPrefixAndExhaustedIdentitiesIncomplete(t *testing.T) {
	for _, mode := range []string{"missing-request-prefix", "exhausted-identity"} {
		t.Run(mode, func(t *testing.T) {
			rows, _, err := readSyncFixture(t, syntheticSyncJournal(t, mode), "journal")
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 3 || rows[0].SyncTrace == nil || rows[0].SyncTrace.Complete == nil || *rows[0].SyncTrace.Complete {
				t.Fatal("incomplete source claimed complete", rows)
			}
			for _, r := range rows[1:] {
				if r.SyncEvidence == nil || r.SyncEvidence.Complete || r.SyncEvidence.Request != nil {
					t.Fatal("invented source relationship", r)
				}
				if r.SyncControl.Stage == "processed" && (r.SyncControl.RequestSource == nil || *r.SyncControl.RequestSource.Available) {
					t.Fatal("missing identity linked to a request", r)
				}
			}
		})
	}
}

func TestSyncJournalDamagedTailDoesNotEmitClosedEvidence(t *testing.T) {
	dir := t.TempDir()
	files, err := os.ReadDir("testdata/sync-combined/journal")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("testdata/sync-combined/journal", file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Ext(file.Name()) == ".wal" {
			raw = append(raw, 0xff)
		}
		if err := os.WriteFile(filepath.Join(dir, file.Name()), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows, _, err := readSyncFixture(t, dir, "journal")
	if err == nil || len(rows) != 0 {
		t.Fatal("damaged prefix emitted closed sync evidence", len(rows), err)
	}
}
