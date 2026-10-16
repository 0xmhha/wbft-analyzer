package ingest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestFollowFailuresIdentifyTheStageWithoutAdvancingOrLeaking(t *testing.T) {
	for _, tc := range []struct{ method, stage, kind, code string }{
		{"eth_blockNumber", "read_head", "rpc", "-32603"},
		{"eth_getBlockByNumber", "read_genesis", "rpc", "-32603"},
		{"wbft_nodeInfo", "capture_observations", "unknown", ""},
		{"wbft_participation", "validate_observations", "participation", ""},
	} {
		t.Run(tc.method, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			wire, c := newFollowRPC(t)
			f, err := OpenFollower(ctx, s, followOptions(t, c, "synthetic-diagnostic"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			before, err := s.FollowState(ctx, f.Dataset.ID)
			if err != nil {
				t.Fatal(err)
			}
			wire.mu.Lock()
			wire.failMethod = tc.method
			wire.mu.Unlock()
			_, err = f.Step(ctx)
			if err == nil {
				t.Fatal("injected failure succeeded")
			}
			d := FollowFailure(err)
			if d.Stage != tc.stage || d.Kind != tc.kind || d.Code != tc.code {
				t.Fatal(d)
			}
			for _, text := range []string{err.Error(), fmt.Sprint(d)} {
				if strings.Contains(text, "redacted.invalid") || strings.Contains(text, "synthetic:example") || strings.Contains(text, "private") {
					t.Fatal("unsafe diagnostic", text)
				}
			}
			if tc.kind == "rpc" {
				var server *rpc.Error
				if !errors.As(err, &server) || server.Code != -32603 {
					t.Fatal("RPC error identity lost")
				}
			}
			if tc.kind == "participation" && !errors.Is(err, ErrFollowIncomplete) {
				t.Fatal("participation retry identity lost")
			}
			after, e := s.FollowState(ctx, f.Dataset.ID)
			if e != nil || before.Cursor != after.Cursor || before.Captured != after.Captured || before.TotalBatches != after.TotalBatches {
				t.Fatal("failure advanced cursor", after, e)
			}
			wire.mu.Lock()
			wire.failMethod = ""
			wire.mu.Unlock()
			if r, e := f.Step(ctx); e != nil || r.Headers != 1 || r.Next != "2" {
				t.Fatal("retry failed after source recovery", r, e)
			}
		})
	}
}

func TestFollowDiagnosticsBoundDatabaseCodesAndPreserveFatalDecisions(t *testing.T) {
	for _, code := range []string{"40P01", "private-uri", "aaaaa", "https://redacted.invalid"} {
		inner := &pgconn.PgError{Code: code, Message: "https://synthetic:example@redacted.invalid/private", Detail: "private"}
		err := &followFailure{stage: "ingest_observations", err: inner}
		d := FollowFailure(fmt.Errorf("wrapped: %w", err))
		want := ""
		if code == "40P01" {
			want = code
		}
		if d.Stage != "ingest_observations" || d.Kind != "database" || d.Code != want || strings.Contains(err.Error(), "private") {
			t.Fatal(d)
		}
		var database *pgconn.PgError
		if !errors.As(err, &database) || database != inner {
			t.Fatal("database error identity lost")
		}
	}
	for _, inner := range []error{ErrFollowIdentity, ErrFollowIncomplete, context.Canceled, context.DeadlineExceeded} {
		err := &followFailure{stage: "validate_observations", err: inner}
		if !errors.Is(err, inner) || FollowFailure(err).Kind == "unknown" {
			t.Fatal("original decision lost")
		}
	}
	if d := FollowFailure(&followFailure{stage: "private-uri", err: errors.New("private")}); d.Stage != "" {
		t.Fatal("unknown stage became a label", d)
	}
	if d := FollowFailure(nil); d != (FollowDiagnostic{}) {
		t.Fatal(d)
	}
}
