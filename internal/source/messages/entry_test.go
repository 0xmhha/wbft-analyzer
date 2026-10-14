package messages

import (
	"context"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
	"math/big"
	"testing"
	"time"
)

func TestEntryEvidencePreservesMeasuredZeroAndLegacyUnknown(t *testing.T) {
	dir := t.TempDir()
	a := types.Address{}
	a[19] = 1
	w, e := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Self: a, Run: "synthetic-entry", ChainID: big.NewInt(7)})
	if e != nil {
		t.Fatal(e)
	}
	for i, entry := range []*journal.StepMoment{nil, {Mono: 0, WallNs: 1577836800000000000}} {
		w.Put(journal.Record{Body: &journal.StepRec{Step: uint64(i + 1), Mono: time.Millisecond, WallNs: 1577836800001000000, Entry: entry}})
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	in := Input{ID: "journal", Kind: "journal", Node: self, Path: dir}
	sum, e := Fingerprint(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	var steps []Record
	_, e = Read(context.Background(), Prepared{Input: in, Summary: sum}, "7", genesis, func(r Record) error {
		if r.Type == "step" {
			steps = append(steps, r)
		}
		return nil
	})
	if e != nil || len(steps) != 2 || steps[0].EntryMono != nil || steps[0].EntryWall != "" || steps[1].EntryMono == nil || *steps[1].EntryMono != "0" || steps[1].EntryWall != "2020-01-01T00:00:00Z" || steps[1].Mono == nil || *steps[1].Mono != "1000000" {
		t.Fatal(steps, e)
	}
}
