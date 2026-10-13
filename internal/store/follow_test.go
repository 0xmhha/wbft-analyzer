package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft/observe/participation"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDatasetLocksLeaveWritePoolAvailable(t *testing.T) {
	s, _ := testStore(t)
	if _, e := s.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	cfg := s.pool.Config()
	cfg.MaxConns = 1
	old := s.pool
	pool, e := pgxpool.NewWithConfig(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	s.pool = pool
	old.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 4; i++ {
		_, release, e := s.BeginRange(ctx, NetworkKey{ChainID: "8", GenesisHash: "synthetic"}, fmt.Sprintf("synthetic-lock-%d", i), json.RawMessage(`{}`))
		if e != nil {
			t.Fatal("dataset locks exhausted write pool", e)
		}
		defer release()
	}
}

func TestFollowCommitRequiresCompleteBoundEvidence(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	a, _, e := observe.Load("../source/observe/testdata/capture.json")
	if e != nil {
		t.Fatal(e)
	}
	snap, e := observe.Normalize(a)
	if e != nil {
		t.Fatal(e)
	}
	key := NetworkKey{ChainID: "8", GenesisHash: snap.Node.GenesisHash.String()}
	meta, _ := json.Marshal(map[string]string{"address": snap.Node.Address.String()})
	f, release, e := s.BeginFollow(ctx, key, "synthetic-cursor", meta, 1, key.GenesisHash)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	h, releaseH, e := s.BeginRange(ctx, key, "synthetic-headers", json.RawMessage(`{"from":"1","to":"2"}`))
	if e != nil {
		t.Fatal(e)
	}
	defer releaseH()
	one := headers.Fact{Index: "1", Number: "1", Hash: "0x2222222222222222222222222222222222222222222222222222222222222222", ParentHash: key.GenesisHash, EpochInfo: json.RawMessage("null")}
	two := one
	two.Index = "2"
	two.Number = "2"
	two.Hash = "0x3333333333333333333333333333333333333333333333333333333333333333"
	two.ParentHash = one.Hash
	copies := []headers.Copy{{Index: "1", Hash: one.Hash, Node: "synthetic"}, {Index: "2", Hash: two.Hash, Node: "synthetic"}}
	if e = s.PutHeaders(ctx, h.ID, h.NetworkID, []headers.Fact{one, two}, copies, 2); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, h.ID, 2, ""); e != nil {
		t.Fatal(e)
	}
	put := func(name string, snap observe.Snapshot) int64 {
		t.Helper()
		o, release, e := s.BeginObservations(ctx, key, name, json.RawMessage(`{}`))
		if e != nil {
			t.Fatal(e)
		}
		defer release()
		if e = s.PutObservation(ctx, o.ID, "archive", strings.Repeat("1", 64), snap); e != nil {
			t.Fatal(e)
		}
		if e = s.FinishRange(ctx, o.ID, int64(len(snap.Calls)), ""); e != nil {
			t.Fatal(e)
		}
		return o.ID
	}
	gapID := put("synthetic-gap", snap)
	if e = s.CommitFollow(ctx, f.ID, 1, 2, key.GenesisHash, two.Hash, h.ID, gapID); !errors.Is(e, ErrFollowCursor) {
		t.Fatal("gap committed", e)
	}
	var records []participation.Record
	for i := range a.Replies {
		var env map[string]json.RawMessage
		_ = json.Unmarshal(a.Replies[i].Response, &env)
		switch a.Replies[i].Method {
		case "wbft_participation":
			_ = json.Unmarshal(env["result"], &records)
			records[1] = records[0]
			records[1].Height = "2"
			records[1].Hash = two.Hash
			env["result"], _ = json.Marshal(records)
		case "wbft_participationSummary":
			env["result"], _ = json.Marshal(participation.Summarize(records))
		}
		a.Replies[i].Response, _ = json.Marshal(env)
	}
	snap, e = observe.Normalize(a)
	if e != nil {
		t.Fatal(e)
	}
	okID := put("synthetic-complete", snap)
	if e = s.CommitFollow(ctx, f.ID, 1, 2, key.GenesisHash, two.Hash, h.ID, okID); e != nil {
		t.Fatal(e)
	}
	state, e := s.FollowState(ctx, f.ID)
	if e != nil || state.Cursor.Next != "3" || state.Captured != 2 || state.TotalBatches != 1 || state.Latest[0].ObservationsDataset != okID {
		t.Fatal(state, e)
	}
	if e = s.CommitFollow(ctx, f.ID, 1, 2, key.GenesisHash, two.Hash, h.ID, okID); !errors.Is(e, ErrFollowCursor) {
		t.Fatal("repeated cursor committed", e)
	}
	if _, e = s.pool.Exec(ctx, `DELETE FROM datasets WHERE id=$1`, okID); e == nil {
		t.Fatal("cursor evidence could be deleted")
	}
}
