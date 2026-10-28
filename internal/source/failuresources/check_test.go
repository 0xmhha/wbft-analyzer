package failuresources

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

func testLimits(t *testing.T) journal.ReceiveFailureLimits {
	t.Helper()
	limits := journal.ReceiveFailureLimits{Caches: 8, Inbox: journal.InboxLimits{Core: journal.CoreSourceLimits{Records: 1000, Runs: 8, Steps: 100, Environments: 100, Outputs: 1000, Bytes: 1 << 20}, Operations: 1000, Entries: 100, Peers: 10, Frames: 100, Bytes: 1 << 20}}
	raw, err := json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Limits(raw)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestReceiveFailureLimitsAndCancellation(t *testing.T) {
	limits := testLimits(t)
	zero := limits
	zero.Inbox.Frames = 0
	raw, err := json.Marshal(zero)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{[]byte(`null`), []byte(`{}`), []byte(`{"Caches":1,"Caches":2}`), []byte(`{"unknown":1}`), []byte(`{} {}`), make([]byte, MaxLimitsBytes+1), raw} {
		if _, err := Limits(input); err == nil {
			t.Fatal("invalid limits accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Check(ctx, t.TempDir(), limits); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

// This writes new local declarations only. They are not executed checks,
// packet mutations, or a physical failure-reuse proof.
func TestReceiveFailureOriginalDeclarationsAndCoreOutcomes(t *testing.T) {
	dir := t.TempDir()
	write := func(entries uint64) {
		t.Helper()
		w, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Run: "original-failure-source", Core: journal.CoreOptions{CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}}, ReceiveFailureCache: &journal.ReceiveFailureCacheOptions{Profile: journal.ReceiveFailureCacheProfile, Entries: entries}}})
		if err != nil {
			t.Fatal(err)
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	limits := testLimits(t)
	for i, entries := range []uint64{2, 3} {
		write(entries)
		records, err := journal.ReadAll(nil, dir)
		if err != nil {
			t.Fatal(err)
		}
		want, wantErr := journal.CheckReceiveFailureSources(records, limits)
		got, gotErr := Check(t.Context(), dir, limits)
		if !reflect.DeepEqual(got, want) || errors.Is(gotErr, journal.ErrReceiveFailureSource) != errors.Is(wantErr, journal.ErrReceiveFailureSource) {
			t.Fatal("original source outcome changed", got, want, gotErr, wantErr)
		}
		if got.PhysicalStatus != "unavailable" || got.VerifiedFailures != 0 || got.ConsumedFailures != 0 || got.Inbox.Checked != 0 {
			t.Fatal("declaration became a check", got)
		}
		if i == 0 && got.Status != "unavailable" || i == 1 && (got.Status != "inconsistent" || got.Reason != "writer_failure_declaration_changed") {
			t.Fatal(got)
		}
	}
	limits.Inbox.Core.Records = 1
	got, err := Check(t.Context(), dir, limits)
	if err != nil || got.Status != "unavailable" || got.Reason != "record_limit" {
		t.Fatal(got, err)
	}
	if err = os.WriteFile(filepath.Join(dir, "unexpected-input"), []byte("not a source"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(t.Context(), dir, testLimits(t)); !errors.Is(err, ErrInput) {
		t.Fatal("unrecognized source file accepted", err)
	}
}
