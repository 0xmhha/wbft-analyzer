package messages

import (
	"errors"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestReceiveFailureProfileRefusesLegacyProjectionAtomically(t *testing.T) {
	for _, profile := range []uint64{journal.ReceiveFailureCacheProfile, 77} {
		in := Input{ID: "failure-source", Kind: "journal", Node: self, Path: t.TempDir()}
		writer, err := journal.Open(journal.Options{Dir: in.Path, Synchronous: true}, journal.Identity{Self: types.Address{19: 1}, Run: "original-failure-source", ChainID: big.NewInt(7), Core: journal.CoreOptions{CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}}, ReceiveFailureCache: &journal.ReceiveFailureCacheOptions{Profile: profile, Entries: 2}}})
		if err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		rows, err := readCacheJournal(t, in)
		if !errors.Is(err, ErrReceiveFailureSource) || len(rows) != 0 {
			t.Fatal("failure source escaped as legacy evidence", len(rows), err)
		}
	}
	// These body-only values test adapter refusal, not a physical capture.
	for _, body := range []any{&journal.ReceiveFailureCacheRec{}, &journal.InboxFailureHitRec{}} {
		if err := newJournalCacheState().project(&Record{}, journal.Record{Body: body}); !errors.Is(err, ErrReceiveFailureSource) {
			t.Fatal("failure body projected", err)
		}
	}
}
