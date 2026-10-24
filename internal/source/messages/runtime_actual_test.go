package messages

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
)

// This optional fixture reads journals from completed normal producers. Local
// release validation supplies it and requires this test to run without skips.
func TestActualRuntimeSourceRefusesLegacyProjection(t *testing.T) {
	root := os.Getenv("WBFT_RUNTIME_JOURNALS_INPUT")
	if root == "" {
		t.Skip("WBFT_RUNTIME_JOURNALS_INPUT is not set")
	}
	for _, run := range []string{"runtime-return-0-0", "runtime-return-4-0"} {
		t.Run(run, func(t *testing.T) {
			path := filepath.Join(root, run)
			rows, err := journal.ReadAll(nil, path)
			if err != nil {
				t.Fatal(err)
			}
			var identity *journal.SegmentRec
			var runtime *journal.RuntimeRec
			for _, row := range rows {
				switch source := row.Body.(type) {
				case *journal.SegmentRec:
					if identity == nil {
						identity = source
					}
				case *journal.RuntimeRec:
					if runtime == nil {
						runtime = source
					}
				}
			}
			if identity == nil || identity.ChainID == nil || runtime == nil {
				t.Fatal("original runtime source missing")
			}
			read := func(path string) ([]Record, error) {
				in := Input{ID: "actual-runtime", Kind: "journal", Node: addr(identity.Self), Path: path}
				summary, e := Fingerprint(t.Context(), in)
				if e != nil {
					t.Fatal(e)
				}
				var projected []Record
				_, e = Read(t.Context(), Prepared{Input: in, Summary: summary}, identity.ChainID.String(), identity.GenesisHash.Hex(), func(r Record) error { projected = append(projected, r); return nil })
				return projected, e
			}
			projected, err := read(path)
			if err == nil || len(projected) != 0 {
				t.Fatal("original unsupported journal exposed legacy rows", len(projected), err)
			}
			// Producers, signers and DBs are closed. Only diagnostic copies below
			// select an actual unchanged runtime return record under legacy headers.
			for _, legacy := range []uint64{0, journal.CacheTraceVersion} {
				t.Run(fmt.Sprint(legacy), func(t *testing.T) {
					copyIdentity := identity.Identity
					copyIdentity.Core.CachePolicy = nil
					copyIdentity.Core.CacheTrace = legacy
					copyIdentity.Core.TimerTrace = 0
					copyDir := t.TempDir()
					w, e := journal.Open(journal.Options{Dir: copyDir, Synchronous: true}, copyIdentity)
					if e != nil {
						t.Fatal(e)
					}
					w.Put(journal.Record{Body: runtime})
					if e = w.Close(); e != nil {
						t.Fatal(e)
					}
					projected, e := read(copyDir)
					if !errors.Is(e, errRuntimeSource) || len(projected) != 0 {
						t.Fatal("actual runtime source used legacy proof", legacy, len(projected), e)
					}
				})
			}
		})
	}
}
