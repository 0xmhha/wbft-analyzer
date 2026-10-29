package store

import (
	"context"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/derive/observation"
	"testing"
)

func TestSuccessorCopiesTailAndProjectionVersion(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, hd, _ := bindingFixtureWithOwnRound(t, s, 1)
	first, err := s.RebuildObservationHeaders(ctx, d.ID)
	if err != nil || first.BoundCopies != 1 || first.Version != observation.Version {
		t.Fatal(first, err)
	}
	node := "0x0000000000000000000000000000000000000001"
	rows, err := s.HeaderRows(ctx, d.NetworkID, "1", "1", &d.ID, node)
	if err != nil || len(rows) != 1 || rows[0].Copy == nil || rows[0].Copy.Round != 1 || rows[0].DecisionRound == nil || *rows[0].DecisionRound != 0 {
		t.Fatal(rows, err)
	}
	other, err := s.HeaderRows(ctx, d.NetworkID, "1", "1", &hd.ID, "independent")
	if err != nil || other[0].Copy == nil || other[0].Copy.Round != 0 || *other[0].DecisionRound != *rows[0].DecisionRound {
		t.Fatal(other, err)
	}
	// The child outside the selected window is used; the stored tail stays unknown.
	tail, err := s.HeaderRows(ctx, d.NetworkID, "2", "3", &hd.ID, "independent")
	if err != nil || len(tail) != 2 || tail[0].DecisionRound == nil || tail[0].ProofHash == nil || tail[1].DecisionRound != nil || tail[1].ExpectedProposer != nil || tail[1].ProposerDiffers != nil || len(tail[1].Missed) != 0 || tail[1].Copy == nil || tail[1].Cells[0].Committed != nil {
		t.Fatal(tail, err)
	}
	sum, err := s.HeaderSummary(ctx, d.NetworkID, 2, 3)
	if err != nil || sum.Heights != 2 || sum.UnknownRound != 1 {
		t.Fatal(sum, err)
	}
	found := false
	for _, v := range sum.Validators {
		if v.Address != node {
			continue
		}
		found = true
		if v.Eligible != 2 || v.Known != 1 || v.Unknown != 1 || v.InclusionRate != nil {
			t.Fatal(v)
		}
	}
	if !found {
		t.Fatal("eligible validator missing", sum)
	}
	// Compatibility metadata only: old semantics must require explicit reindex.
	if _, err = s.pool.Exec(ctx, `UPDATE observation_header_indexes SET version=$2 WHERE dataset_id=$1`, d.ID, "wbft-observation-headers/1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = s.ObservationHeaderIndex(ctx, d.ID); !errors.Is(err, ErrObservationHeaderIndex) {
			t.Fatal("GET accepted or rebuilt old semantics", err)
		}
	}
	if _, err = s.HeaderRows(ctx, d.NetworkID, "1", "1", &d.ID, node); !errors.Is(err, ErrObservationHeaderIndex) {
		t.Fatal("old bound copy was served", err)
	}
	again, err := s.RebuildObservationHeaders(ctx, d.ID)
	if err != nil || again.Snapshot != first.Snapshot || again.BoundCopies != 1 {
		t.Fatal(again, err)
	}
}
