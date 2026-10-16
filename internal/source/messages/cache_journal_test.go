package messages

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func cacheJournalFixture(t *testing.T, mode string) Input {
	t.Helper()
	in := Input{ID: "cache-journal", Kind: "journal", Node: self, Path: t.TempDir()}
	node, peer := types.Address{19: 1}, types.Address{19: 2}
	cap := uint64(1)
	if mode == "no capability" {
		cap = 0
	}
	w, e := journal.Open(journal.Options{Dir: in.Path, Synchronous: true, SegmentBytes: 600}, journal.Identity{Self: node, Run: "cache-writer", ChainID: big.NewInt(7), Core: journal.CoreOptions{CacheTrace: cap}})
	if e != nil {
		t.Fatal(e)
	}
	payload := vote(t, codec.CodePrepare)
	key := codec.DedupKey(payload)
	sum := types.Hash(sha256.Sum256(payload))
	w.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peer, Event: "attached", Remote: "NEVER_STORED"}})
	if mode != "missing instance" {
		w.Put(journal.Record{Body: &journal.CacheRec{Instance: 1, Action: "begin", Self: node, PeerCapacity: 40, MessageCapacity: 1024}})
	}
	w.Put(journal.Record{Body: &journal.CacheRec{Instance: 1, Sequence: 1, Action: "gossip", Code: 0x13, Key: key, PayloadSHA256: sum, Cause: event.SendCause("retry"), Available: true, Candidates: []types.Address{peer}, Targets: []types.Address{peer}, Mono: 1, WallNs: 1577836800000000001}})
	w.Put(journal.Record{Body: &journal.CacheRec{Instance: 1, Sequence: 2, Action: "gossip", Code: 0x13, Key: key, PayloadSHA256: sum, Cause: event.SendCause("relay"), Available: true, Known: true, Candidates: []types.Address{peer}, Suppressed: []types.Address{peer}, Mono: 2, WallNs: 1577836800000000002}})
	w.Put(journal.Record{Body: &journal.SuppressedRec{PeerIdx: 1, DedupKey: key, Cause: event.SendCause("relay"), Reason: "peer_recent_cache", Cache: 1, Operation: 2}})
	if mode == "gap" {
		w.Put(journal.Record{Body: &journal.GapRec{Dropped: 1}})
	}
	attempt := &journal.SendAttempt{Sequence: 9, Cache: 1, Operation: 1}
	cause := event.SendCause("retry")
	if mode == "held write" {
		attempt.Operation = 2
		cause = "relay"
	}
	if mode == "wrong context" {
		cause = "broadcast"
	}
	if mode == "missing operation" {
		attempt.Operation = 3
	}
	if mode == "unknown attempt" {
		attempt = nil
	}
	w.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, PeerIdx: 1, Code: 0x13, Payload: payload, DedupKey: key, Write: "ok", Cause: cause, Attempt: attempt, Mono: 3, WallNs: 1577836800000000003}})
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return in
}
func readCacheJournal(t *testing.T, in Input) ([]Record, error) {
	t.Helper()
	sum, e := Fingerprint(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	var rows []Record
	_, e = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(r Record) error { rows = append(rows, r); return nil })
	return rows, e
}
func TestCacheJournalSnapshotSpansRealSegments(t *testing.T) {
	in := cacheJournalFixture(t, "")
	rows, e := readCacheJournal(t, in)
	if e != nil {
		t.Fatal(e)
	}
	files := map[string]bool{}
	byPoint := map[OwnSourcePoint]Record{}
	var frame Record
	declarations, ops := 0, 0
	for _, r := range rows {
		files[r.File] = true
		byPoint[ownPoint(r)] = r
		if r.CacheTrace != nil {
			declarations++
			if r.CacheTrace.Instances != "1" || r.CacheTrace.Operations != "2" || r.CacheTrace.Complete == nil || !*r.CacheTrace.Complete || r.Mono != nil || r.Wall != "" {
				t.Fatal("raw declaration changed", r)
			}
		}
		if r.CacheOperation != nil {
			ops++
		}
		if r.Type == "frame" {
			frame = r
		}
	}
	if len(files) < 2 || declarations != 1 || ops != 2 || frame.CacheEvidence == nil || frame.SendAttempt == nil || frame.SendAttempt.Sequence != "9" {
		t.Fatal("segmented cache context lost", len(files), declarations, ops, frame)
	}
	original := byPoint[frame.CacheEvidence.Operation]
	if original.CacheOperation == nil || original.CacheOperation.Sequence != "1" || original.Journal == nil || frame.SendAttempt.Decision.Offset != original.Journal.Offset || frame.SendAttempt.Decision.Segment != original.Journal.Segment || frame.CacheEvidence.Operation.File == frame.File {
		t.Fatal("raw operation source aliased to frame file", frame, original)
	}
	b, e := json.Marshal(rows)
	if e != nil || strings.Contains(string(b), "NEVER_STORED") || strings.Contains(string(b), "\"Attempt\"") {
		t.Fatal("unrestricted journal bytes persisted", e, string(b))
	}
}
func TestCacheJournalUnavailableAndActualContradiction(t *testing.T) {
	for _, mode := range []string{"gap", "missing instance", "missing operation", "unknown attempt", "held write"} {
		t.Run(mode, func(t *testing.T) {
			rows, e := readCacheJournal(t, cacheJournalFixture(t, mode))
			if e != nil {
				t.Fatal(e)
			}
			var frame Record
			for _, r := range rows {
				if r.Type == "frame" {
					frame = r
				}
			}
			if mode == "held write" {
				if frame.Write != "ok" || frame.CacheEvidence == nil || frame.SendAttempt.Decision.Operation != "2" {
					t.Fatal("actual suppressed write hidden", frame)
				}
			} else if frame.CacheEvidence != nil {
				t.Fatal("missing context fabricated exact provenance", frame)
			}
		})
	}
}
func TestCacheJournalRefusesForgedOrChangingSourceAtomically(t *testing.T) {
	for _, mode := range []string{"no capability", "wrong context", "torn tail", "fingerprint"} {
		t.Run(mode, func(t *testing.T) {
			in := cacheJournalFixture(t, mode)
			if mode == "torn tail" {
				files, e := filepath.Glob(filepath.Join(in.Path, "*.wal"))
				if e != nil {
					t.Fatal(e)
				}
				f, e := os.OpenFile(files[len(files)-1], os.O_APPEND|os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.Write([]byte{1, 2, 3})
				if e != nil {
					t.Fatal(e)
				}
				_ = f.Close()
			}
			sum, e := Fingerprint(context.Background(), in)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "fingerprint" {
				sum.SHA256 = strings.Repeat("0", 64)
			}
			emitted := 0
			_, e = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(Record) error { emitted++; return nil })
			if e == nil || emitted != 0 {
				t.Fatal("invalid raw snapshot emitted metadata", mode, e, emitted)
			}
		})
	}
}
