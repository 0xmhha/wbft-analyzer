package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// testStore opens a store on a schema of its own in the database of
// WBFT_ANALYZER_TEST_DSN, dropped when the test ends. Tests do not depend
// on each other's state (design.md 7).
func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	dsn := os.Getenv("WBFT_ANALYZER_TEST_DSN")
	if dsn == "" {
		t.Skip("WBFT_ANALYZER_TEST_DSN is not set")
	}
	ctx := context.Background()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	schema := "t_" + hex.EncodeToString(b)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = conn.Close(context.Background())
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	s, err := Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, schema
}

func report(id string) *Report {
	return &Report{ID: id, RunID: "run-1", StartedAt: "2026-10-12T00:00:00Z", FinishedAt: "2026-10-12T00:00:01Z",
		InspectorVersion: "0.1.0", InspectorCommit: "c59b1c5", CatalogSHA256: strings.Repeat("a", 64), SpecCommit: "1c91f50",
		Summary: json.RawMessage(`{"exit_code":0}`),
		Results: []Result{{Requirement: "WBFT-SM-083", Verdict: "PASS", Coverage: json.RawMessage(`{"instances":3}`)},
			{Requirement: "WBFT-SM-083", Node: "0xaa", Verdict: "PASS"}},
		Observations: []Observation{{ID: "o1", Kind: "late_seal", Imp: []string{}, Count: 4}}}
}

// TestMigrate applies the migrations once: a second run changes nothing.
func TestMigrate(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	v, err := s.Migrate(ctx)
	if err != nil || v != 13 {
		t.Fatalf("migrate: version %d, %v", v, err)
	}
	if v, err := s.Migrate(ctx); err != nil || v != 13 {
		t.Fatalf("migrate again: version %d, %v", v, err)
	}
}

// TestPutReport stores a report with its rows; the same report again is
// skipped and adds no row.
func TestPutReport(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("1", 64)
	if added, _, err := s.PutReport(ctx, report(id)); err != nil || !added {
		t.Fatalf("first put: %v %v", added, err)
	}
	if added, _, err := s.PutReport(ctx, report(id)); err != nil || added {
		t.Fatalf("second put: %v %v", added, err)
	}
	if r, o, err := s.ReportCounts(ctx, id); err != nil || r != 2 || o != 1 {
		t.Fatalf("counts %d %d %v", r, o, err)
	}
	if _, _, err := s.ReportCounts(ctx, strings.Repeat("2", 64)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing report: %v", err)
	}
	// A report whose rows break a constraint leaves nothing behind.
	bad := report(strings.Repeat("3", 64))
	bad.Results = append(bad.Results, bad.Results[0])
	if _, _, err := s.PutReport(ctx, bad); err == nil {
		t.Fatal("a duplicate result row was stored")
	}
	if _, _, err := s.ReportCounts(ctx, bad.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a failed put left the report: %v", err)
	}
}

// TestNewerSchema refuses a database migrated by a newer build.
func TestNewerSchema(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES (99, '0099_future.sql')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "newer than this build") {
		t.Fatalf("migrate on a newer schema: %v", err)
	}
}
