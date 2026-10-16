package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
)

func bindingFixture(t *testing.T, s *Store) (Dataset, Dataset, []headers.Fact) {
	t.Helper()
	ctx := context.Background()
	a, sha, e := observe.Load("../source/observe/testdata/capture.json")
	if e != nil {
		t.Fatal(e)
	}
	snap, e := observe.Normalize(a)
	if e != nil {
		t.Fatal(e)
	}
	key := NetworkKey{ChainID: "8", GenesisHash: snap.Node.GenesisHash.String()}
	d, release, e := s.BeginObservations(ctx, key, "synthetic-bound-observation", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	if e = s.PutObservation(ctx, d.ID, "archive", sha, snap); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, d.ID, int64(len(snap.Calls)), ""); e != nil {
		t.Fatal(e)
	}
	hd, release, e := s.BeginRange(ctx, key, "independent-binding-headers", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	facts := []headers.Fact{}
	copies := []headers.Copy{}
	for i := 0; i < 4; i++ {
		hash := fmt.Sprintf("0x%s", strings.Repeat(fmt.Sprint(i+1), 64))
		parent := "0x" + strings.Repeat(fmt.Sprint(i), 64)
		f := headers.Fact{Index: fmt.Sprint(i), Number: fmt.Sprint(i), Hash: hash, ParentHash: parent, Validators: []string{"0x0000000000000000000000000000000000000001"}, Coinbase: "0x0000000000000000000000000000000000000001", Policy: "0", LastProposer: "0x0000000000000000000000000000000000000001", EpochInfo: json.RawMessage(`null`), PrevPrepared: []int64{0}, PrevCommitted: []int64{0}}
		facts = append(facts, f)
		copies = append(copies, headers.Copy{Index: f.Index, Hash: f.Hash, Node: "independent", Round: 0, Prepared: []int64{0}, Committed: []int64{0}})
	}
	if e = s.PutHeaders(ctx, hd.ID, hd.NetworkID, facts, copies, 4); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, hd.ID, 4, ""); e != nil {
		t.Fatal(e)
	}
	return d, hd, facts
}
func TestObservationBindingAtomicCopiesAndStaleDependencies(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	d, _, _ := bindingFixture(t, s)
	node := "0x0000000000000000000000000000000000000001"
	if _, e := s.ObservationHeaderIndex(ctx, d.ID); !errors.Is(e, ErrObservationHeaderIndex) {
		t.Fatal("GET rebuilt binding", e)
	}
	first, e := s.RebuildObservationHeaders(ctx, d.ID)
	if e != nil || first.BoundCopies != 1 || first.Rows != 4 {
		t.Fatal(first, e)
	}
	again, e := s.RebuildObservationHeaders(ctx, d.ID)
	if e != nil || again.Snapshot != first.Snapshot {
		t.Fatal("rebuild not deterministic", again, e)
	}
	rows, e := s.HeaderRows(ctx, d.NetworkID, "1", "1", &d.ID, node)
	if e != nil || rows[0].Copy == nil || rows[0].Copy.Source != "rpc_observation_structural" || rows[0].Copy.Round != 0 {
		t.Fatal(rows, e)
	}
	// A formerly unknown carrier must invalidate all copy consumers too.
	if _, e = s.pool.Exec(ctx, `DELETE FROM seals WHERE network_id=$1 AND index_=3`, d.NetworkID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `DELETE FROM heights WHERE network_id=$1 AND index_=3`, d.NetworkID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ObservationHeaderIndex(ctx, d.ID); !errors.Is(e, ErrObservationHeaderIndex) {
		t.Fatal("header deletion accepted", e)
	}
	if _, e = s.HeaderRows(ctx, d.NetworkID, "1", "1", &d.ID, node); !errors.Is(e, ErrObservationHeaderIndex) {
		t.Fatal("stale overlay served", e)
	}
	if e = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return checkObservationCopies(ctx, tx, d.NetworkID) }); !errors.Is(e, ErrObservationHeaderIndex) {
		t.Fatal("stale copy available for missing projection", e)
	}
	if _, e = s.RebuildObservationHeaders(ctx, d.ID); e != nil {
		t.Fatal(e)
	}
	// The source is immutable, but a damaged underlying metadata row is stale.
	if _, e = s.pool.Exec(ctx, `UPDATE observation_calls SET call=jsonb_set(call,'{status}','"unavailable"') WHERE dataset_id=$1 AND ordinal=5`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ObservationHeaderIndex(ctx, d.ID); !errors.Is(e, ErrObservationHeaderIndex) {
		t.Fatal("source-only change accepted", e)
	}
	changed, e := s.RebuildObservationHeaders(ctx, d.ID)
	if e != nil || changed.BoundCopies != 0 {
		t.Fatal("unavailable copy survived rebuild", changed, e)
	}
	rows, e = s.HeaderRows(ctx, d.NetworkID, "1", "1", &d.ID, node)
	if e != nil || rows[0].Copy != nil {
		t.Fatal("obsolete structural copy retained", rows, e)
	}
	// Failed rebuild leaves the previous index and rows atomically intact.
	var originalProgress int64
	if e = s.pool.QueryRow(ctx, `SELECT progress FROM datasets WHERE id=$1`, d.ID).Scan(&originalProgress); e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET progress=progress+1 WHERE id=$1`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RebuildObservationHeaders(ctx, d.ID); e == nil {
		t.Fatal("damaged source rebuilt")
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET progress=$2 WHERE id=$1`, d.ID, originalProgress); e != nil {
		t.Fatal(e)
	}
	restored, e := s.ObservationHeaderIndex(ctx, d.ID)
	if e != nil || restored.Snapshot != changed.Snapshot {
		t.Fatal("failed rebuild destroyed prior index", restored, e)
	}
}
