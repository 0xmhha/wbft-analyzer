package retrysources

import (
	"errors"
	"testing"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
)

// Fresh unsigned source metadata tests decoding dispatch, not live faults.
func TestDomainSourceFutureAndMalformedRemainDistinct(t *testing.T) {
	for _, version := range []uint64{2, 3} {
		dir := t.TempDir()
		writer, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Run: "unsigned-source-model"})
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		body, err := rlp.Encode(struct {
			Format, JSeq uint64
			Source       journal.SignerRec
		}{journal.Format, 2, journal.SignerRec{Source: privval.Source{Version: version}}})
		if err != nil {
			t.Fatal(err)
		}
		log, _, err := wal.OpenOS(dir, wal.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(wal.Record{Format: journal.Format, Kind: uint8(journal.KindSigner), Body: body}); err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		result, err := Check(t.Context(), dir, testLimits(t))
		if version == 3 {
			if err != nil || result.Status != "unavailable" || result.Reason != "unsupported_source_profile" || result.PhysicalStatus != "unavailable" {
				t.Fatal(result, err)
			}
		} else if !errors.Is(err, ErrInput) {
			t.Fatal("supported malformed source mislabeled", result, err)
		}
	}
}
