package store

import (
	"context"
	"encoding/json"
	"errors"
	derived "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMessagePairSnapshotDirectionAndAtomicRollback(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	d, release, e := s.BeginMessages(ctx, NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-pairs", json.RawMessage(`{"clock":{"model":"shared-host"}}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	records := []source.Record{}
	for i, n := range []string{"a", "b"} {
		if e = s.PutMessageInput(ctx, d.ID, source.Summary{ID: n, Node: n}); e != nil {
			t.Fatal(e)
		}
		peer := "b"
		if n == "b" {
			peer = "a"
		}
		dir, wall := "out", "2020-01-01T00:00:00.000000001Z"
		if i == 1 {
			dir, wall = "in", "2020-01-01T00:00:00.010000001Z"
		}
		records = append(records, source.Record{Input: n, File: "00000000000000000000.wal", Ordinal: 1, Seq: "1", Node: n, Run: "r", Type: "frame", Dir: dir, Peer: peer, Key: "bytes", Phase: "PREPARE", Decode: "decoded", Height: "18446744073709551617", Round: "0", Wall: wall, Write: "ok"})
	}
	if e = s.PutMessageRecords(ctx, d.ID, records, 2); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, d.ID, 2, ""); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.MessagePairData(ctx, d.ID, PairFilter{}); !errors.Is(e, ErrPairIndex) {
		t.Fatal(e)
	}
	index, e := s.RebuildMessagePairs(ctx, d.ID)
	if e != nil || index.Pairs != 1 || index.Records != 2 || index.Issues != 0 {
		t.Fatal(index, e)
	}
	_, pairs, e := s.MessagePairData(ctx, d.ID, PairFilter{Sender: "a", Receiver: "b", Height: "18446744073709551617"})
	if e != nil || len(pairs) != 1 || pairs[0].Status != "valid" || *pairs[0].Seconds != .01 {
		t.Fatal(pairs, e)
	}
	again, e := s.RebuildMessagePairs(ctx, d.ID)
	if e != nil || !reflect.DeepEqual(index, again) {
		t.Fatal(index, again, e)
	}
	from, _ := time.Parse(time.RFC3339Nano, records[0].Wall)
	_, after, e := s.MessagePairData(ctx, d.ID, PairFilter{From: from.Add(time.Nanosecond)})
	if e != nil || len(after) != 0 {
		t.Fatal(after, e)
	}
	// A repeated send elsewhere in the dataset prevents a unique in-window pair.
	repeat := records[0]
	repeat.Ordinal = 2
	repeat.Seq = "2"
	repeat.Wall = "2020-01-01T01:00:00Z"
	if e = s.PutMessageRecords(ctx, d.ID, []source.Record{repeat}, 3); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.MessagePairData(ctx, d.ID, PairFilter{}); !errors.Is(e, ErrPairIndex) {
		t.Fatal("append did not invalidate", e)
	}
	_, e = s.RebuildMessagePairs(ctx, d.ID)
	if e != nil {
		t.Fatal(e)
	}
	_, ambiguous, e := s.MessagePairData(ctx, d.ID, PairFilter{})
	if e != nil || len(ambiguous) != 1 || ambiguous[0].Status != "ambiguous" || ambiguous[0].Seconds != nil {
		t.Fatal(ambiguous, e)
	}
	// A rebuild failure rolls back deletion/insertion and retains the old index.
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET progress=4 WHERE id=$1`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RebuildMessagePairs(ctx, d.ID); e == nil {
		t.Fatal("mismatched progress accepted")
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET progress=3 WHERE id=$1`, d.ID); e != nil {
		t.Fatal(e)
	}
	_, restored, e := s.MessagePairData(ctx, d.ID, PairFilter{})
	if e != nil || !reflect.DeepEqual(ambiguous, restored) {
		t.Fatal(restored, e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET metadata='{"clock":{"model":"unknown"}}'::jsonb WHERE id=$1`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.MessagePairData(ctx, d.ID, PairFilter{}); !errors.Is(e, ErrPairIndex) {
		t.Fatal("clock change not invalidated", e)
	}
}

func TestUnknownPeerRetainsEvidenceIssue(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	d, release, e := s.BeginMessages(ctx, NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("0", 64)}, "unknown", json.RawMessage(`{"clock":{"model":"unknown"}}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	if e = s.PutMessageInput(ctx, d.ID, source.Summary{ID: "a", Node: "a"}); e != nil {
		t.Fatal(e)
	}
	r := source.Record{Input: "a", File: "frames-synthetic.jsonl", Ordinal: 7, Node: "a", Run: "r", Seq: "1", Type: "frame", Dir: "in", Key: "bytes", Phase: "COMMIT", Wall: "2020-01-01T00:00:00Z"}
	if e = s.PutMessageRecords(ctx, d.ID, []source.Record{r}, 1); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, d.ID, 1, "prefix incomplete"); e != nil {
		t.Fatal(e)
	}
	index, e := s.RebuildMessagePairs(ctx, d.ID)
	if e != nil || index.Status != "failed" || index.Pairs != 0 || index.Issues != 1 || index.Diagnostics["unknown_peer"] != 1 {
		t.Fatal(index, e)
	}
	issues, e := s.MessagePairIssues(ctx, d.ID, 0, 1)
	if e != nil || len(issues) != 1 || issues[0].Reason != "unknown_peer" || issues[0].Source.Ordinal != 7 {
		t.Fatal(issues, e)
	}
	if _, e = s.pool.Exec(ctx, `DELETE FROM datasets WHERE id=$1`, d.ID); e != nil {
		t.Fatal(e)
	}
	var count int64
	if e = s.pool.QueryRow(ctx, `SELECT count(*) FROM message_pair_issues WHERE dataset_id=$1`, d.ID).Scan(&count); e != nil || count != 0 {
		t.Fatal(count, e)
	}
	// Keep the package reference explicit: no artificial valid sample exists.
	if derived.Summarize(nil).Pairs != 0 {
		t.Fatal("empty pairing has samples")
	}
}
