package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
)

func TestRangeFactsAndCopies(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key := NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64), Name: "test"}
	meta := json.RawMessage(`{"from":"1","to":"1","config_sha256":"x"}`)
	d, release, err := s.BeginRange(ctx, key, "range", meta)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, _, err := s.BeginRange(ctx, key, "range", meta); err == nil {
		t.Fatal("concurrent importer acquired the dataset")
	}
	a := "0x0000000000000000000000000000000000000001"
	b := "0x0000000000000000000000000000000000000002"
	f := headers.Fact{Index: "1", Number: "18446744073709551617", Hash: "one", Epoch: "0", Validators: []string{a, b}, RoundZero: a, Coinbase: b, LastProposer: "0x" + strings.Repeat("0", 40), Policy: "0", PrevPrepared: []int64{}, PrevCommitted: []int64{}, EpochInfo: json.RawMessage("null")}
	child := f
	child.Index = "2"
	child.Number = "18446744073709551618"
	child.Hash = "two"
	child.ParentHash = "one"
	child.PrevPrepared = []int64{0, 1}
	child.PrevCommitted = []int64{1}
	child.PrevRound = 1
	copy := headers.Copy{Index: "1", Hash: "one", Node: "a", Prepared: []int64{0}, Committed: []int64{}}
	copyChild := copy
	copyChild.Index = "2"
	copyChild.Hash = "two"
	for _, node := range []string{"a", "b"} {
		copy.Node = node
		copyChild.Node = node
		if err := s.PutHeaders(ctx, d.ID, d.NetworkID, []headers.Fact{f, child}, []headers.Copy{copy, copyChild}, 1); err != nil {
			t.Fatal(err)
		}
	}
	var facts, copies, seals int
	if err := s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM heights),(SELECT count(*) FROM header_copies),(SELECT count(*) FROM seals)`).Scan(&facts, &copies, &seals); err != nil {
		t.Fatal(err)
	}
	if facts != 2 || copies != 4 || seals != 2 {
		t.Fatal(facts, copies, seals)
	}
	id := d.ID
	rows, err := s.HeaderRows(ctx, d.NetworkID, "1", "1", &id, "b")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Fact.Number != f.Number || !*rows[0].Cells[1].LateCommitted || rows[0].Copy.Node != "b" {
		t.Fatal(rows)
	}
	summary, err := s.HeaderSummary(ctx, d.NetworkID, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Heights != 2 || summary.MissingHeights != 1 || summary.UnknownRound != 1 || len(summary.Rounds) != 1 || summary.Validators[0].Eligible != 2 || summary.Validators[0].Unknown != 1 || summary.Validators[0].InclusionRate != nil {
		t.Fatal(summary)
	}
	// A conflict rolls back every row in the batch, including an earlier new row.
	newFact := f
	newFact.Index = "3"
	newFact.Hash = "three"
	newCopy := copy
	newCopy.Index = "3"
	newCopy.Hash = "three"
	conflicting := f
	conflicting.Coinbase = a
	if err := s.PutHeaders(ctx, d.ID, d.NetworkID, []headers.Fact{newFact, conflicting}, []headers.Copy{newCopy, copy}, 2); err == nil {
		t.Fatal("canonical conflict overwritten")
	}
	bounds, err := s.HeaderBounds(ctx, d.NetworkID)
	if err != nil || bounds.Count != 2 {
		t.Fatal(bounds, err)
	}
	if err := s.FinishRange(ctx, d.ID, 1, "test failure"); err != nil {
		t.Fatal(err)
	}
	release()
	resumed, release, err := s.BeginRange(ctx, key, "range", meta)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if resumed.ID != d.ID || resumed.Status != "failed" {
		t.Fatal(resumed)
	}
	if _, _, err := s.BeginRange(ctx, key, "range", json.RawMessage(`{"from":"2"}`)); err == nil {
		t.Fatal("different range reused the name")
	}
}

func TestEpochDescriptionInputLimits(t *testing.T) {
	info := json.RawMessage(`{"Candidates":[{"Addr":"0x0000000000000000000000000000000000000001","Diligence":1900000}],"Validators":[0],"BLSPublicKeys":["AQ=="]}`)
	e := Epoch{Index: "140", Info: info}
	if err := describeEpoch(&e, nil); err != nil {
		t.Fatal(err)
	}
	if e.ChangesKnown || len(e.Added) != 0 || e.Candidates[0].Diligence != "1900000" || *e.Candidates[0].ValidatorOrder != 0 || *e.Candidates[0].BLSKey != "0x01" {
		t.Fatal(e)
	}
	e.Index = "0"
	if err := describeEpoch(&e, nil); err != nil {
		t.Fatal(err)
	}
	if !e.ChangesKnown || len(e.Added) != 1 {
		t.Fatal(e)
	}
	e.Index = "140"
	if err := describeEpoch(&e, info); err != nil {
		t.Fatal(err)
	}
	if !e.ChangesKnown || len(e.Added) != 0 || len(e.Removed) != 0 {
		t.Fatal(e)
	}
}
