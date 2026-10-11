// Package store is the analyzer's PostgreSQL store (design.md 7): the
// schema migrations and the writes and reads of the tables.
package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is a connection pool on the analyzer's database.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to the database at dsn (postgres://...). A search_path
// in the DSN selects the schema.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close closes the pool.
func (s *Store) Close() { s.pool.Close() }

// migration is one numbered SQL file.
type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || !strings.HasSuffix(e.Name(), ".sql") {
			return nil, fmt.Errorf("store: migration file %q is not NNNN_name.sql", e.Name())
		}
		b, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: e.Name(), sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("store: migration %s: want version %d", m.name, i+1)
		}
	}
	return out, nil
}

// Migrate applies the migrations the database does not have yet, each in
// its own transaction, and returns the schema version.
func (s *Store) Migrate(ctx context.Context) (int, error) {
	ms, err := loadMigrations()
	if err != nil {
		return 0, err
	}
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	var have int
	if err := s.pool.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&have); err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	if have > len(ms) {
		return have, fmt.Errorf("store: the database is at schema version %d, newer than this build (%d)", have, len(ms))
	}
	for _, m := range ms[have:] {
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name)
			return err
		})
		if err != nil {
			return have, fmt.Errorf("store: migration %s: %w", m.name, err)
		}
		have = m.version
	}
	return have, nil
}

// Report is the row of a report with its results and observations.
type Report struct {
	ID               string // sha256 of the file
	RunID            string
	StartedAt        string
	FinishedAt       string
	InspectorVersion string
	InspectorCommit  string
	CatalogSHA256    string
	SpecCommit       string
	Network          json.RawMessage
	Range            json.RawMessage
	Summary          json.RawMessage
	Results          []Result
	Observations     []Observation
}

// Result is the verdict of one requirement (Node empty for the whole run).
type Result struct {
	Requirement string
	Node        string
	Verdict     string
	Coverage    json.RawMessage
}

// Observation is a finding of a report that is not a verdict.
type Observation struct {
	ID           string
	Kind         string
	Imp          []string
	Requirements []string
	Node         string
	Count        int64
	First, Last  string
}

// ErrNotFound is a row that is not in the store.
var ErrNotFound = errors.New("store: not found")

// PutReport stores a report with its results and observations in one
// transaction. A report whose ID is already stored is skipped: added is
// false and nothing changes.
func (s *Store) PutReport(ctx context.Context, r *Report) (added bool, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO reports (id, run_id, started_at, finished_at, inspector_version, inspector_commit,
			catalog_sha256, spec_commit, network, range_, summary) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (id) DO NOTHING`,
			r.ID, r.RunID, r.StartedAt, r.FinishedAt, r.InspectorVersion, r.InspectorCommit, r.CatalogSHA256, r.SpecCommit,
			nullJSON(r.Network), nullJSON(r.Range), r.Summary)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		added = true
		for _, x := range r.Results {
			if _, err := tx.Exec(ctx, `INSERT INTO results (report_id, requirement, node, verdict, coverage) VALUES ($1, $2, $3, $4, $5)`,
				r.ID, x.Requirement, x.Node, x.Verdict, nullJSON(x.Coverage)); err != nil {
				return err
			}
		}
		for _, o := range r.Observations {
			if _, err := tx.Exec(ctx, `INSERT INTO observations (report_id, obs_id, kind, imp, requirements, node, count, first_at, last_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
				r.ID, o.ID, o.Kind, nonNil(o.Imp), nonNil(o.Requirements), o.Node, o.Count, o.First, o.Last); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("store: report %s: %w", r.ID, err)
	}
	return added, nil
}

// ReportCounts returns the number of results and observations of a stored
// report.
func (s *Store) ReportCounts(ctx context.Context, id string) (results, observations int, err error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM reports WHERE id = $1`, id).Scan(&n); err != nil {
		return 0, 0, fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return 0, 0, ErrNotFound
	}
	err = s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM results WHERE report_id = $1), (SELECT count(*) FROM observations WHERE report_id = $1)`,
		id).Scan(&results, &observations)
	if err != nil {
		return 0, 0, fmt.Errorf("store: %w", err)
	}
	return results, observations, nil
}

func nullJSON(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
