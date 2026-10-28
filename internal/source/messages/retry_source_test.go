package messages

import (
	"errors"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestRetryProfileRefusesLegacyProjectionAtomically(t *testing.T) {
	for _, cache := range []uint64{0, journal.CacheTraceVersion} {
		in := Input{ID: "retry-source", Kind: "journal", Node: self, Path: t.TempDir()}
		writer, err := journal.Open(journal.Options{Dir: in.Path, Synchronous: true}, journal.Identity{Self: types.Address{19: 1}, Run: "normal-retry-source", ChainID: big.NewInt(7), Core: journal.CoreOptions{CacheTrace: cache, RoundChangeRetry: &journal.RoundChangeRetryOptions{Profile: journal.RoundChangeRetryProfile, MaxIntervalMs: 8000}}})
		if err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		rows, err := readCacheJournal(t, in)
		if !errors.Is(err, ErrRetrySource) || len(rows) != 0 {
			t.Fatal("retry source escaped as legacy cache evidence", len(rows), err)
		}
	}
}
