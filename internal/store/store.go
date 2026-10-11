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
	// Network is the network of the run, nil when the report names none
	// (run.network without chain_id and genesis_hash).
	NetworkKey *NetworkKey
	// Points are the observation rates of the report (trends), empty
	// when the report has no range.
	Points []TrendPoint
}

// NetworkKey identifies a network: chain ID and genesis hash. Name is
// used when the network is new.
type NetworkKey struct {
	ChainID     string
	GenesisHash string
	Name        string
}

// TrendPoint is the rate of one observation kind (and node, empty for all
// nodes) in one report.
type TrendPoint struct {
	Report string
	At     string
	Kind   string
	Node   string
	Rate   float64
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
//
// The network of the report is created when it is new (public), and its
// ID returned (0 without a network); the report's trend points go with
// it.
func (s *Store) PutReport(ctx context.Context, r *Report) (added bool, networkID int64, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var nid *int64
		if k := r.NetworkKey; k != nil {
			var id int64
			if err := tx.QueryRow(ctx, `INSERT INTO networks (chain_id, genesis_hash, name, visibility) VALUES ($1, $2, $3, 'public')
				ON CONFLICT (chain_id, genesis_hash) DO UPDATE SET chain_id = EXCLUDED.chain_id RETURNING id`,
				k.ChainID, k.GenesisHash, k.Name).Scan(&id); err != nil {
				return err
			}
			nid, networkID = &id, id
		}
		tag, err := tx.Exec(ctx, `INSERT INTO reports (id, run_id, started_at, finished_at, inspector_version, inspector_commit,
			catalog_sha256, spec_commit, network, range_, summary, network_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO NOTHING`,
			r.ID, r.RunID, r.StartedAt, r.FinishedAt, r.InspectorVersion, r.InspectorCommit, r.CatalogSHA256, r.SpecCommit,
			nullJSON(r.Network), nullJSON(r.Range), r.Summary, nid)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		added = true
		for _, p := range r.Points {
			if _, err := tx.Exec(ctx, `INSERT INTO trend_points (report_id, network_id, kind, node, rate, at) VALUES ($1, $2, $3, $4, $5, $6)`,
				r.ID, nid, p.Kind, p.Node, p.Rate, p.At); err != nil {
				return err
			}
		}
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
		return false, 0, fmt.Errorf("store: report %s: %w", r.ID, err)
	}
	return added, networkID, nil
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

// Series returns the trend points of a network for a kind and node (empty
// for all nodes), in report time order.
func (s *Store) Series(ctx context.Context, networkID int64, kind, node string) ([]TrendPoint, error) {
	rows, err := s.pool.Query(ctx, `SELECT report_id, at, kind, node, rate FROM trend_points
		WHERE network_id = $1 AND kind = $2 AND node = $3 ORDER BY at, report_id`, networkID, kind, node)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (TrendPoint, error) {
		var p TrendPoint
		err := r.Scan(&p.Report, &p.At, &p.Kind, &p.Node, &p.Rate)
		return p, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return out, nil
}

// AlertRule is an alert rule of a network (design.md 6.7, 2).
type AlertRule struct {
	ID        int64
	NetworkID int64
	Kind      string
	Node      string
	Window    int
	Baseline  int
	Mode      string
	Threshold float64
	Webhook   string
}

// AddAlertRule stores a rule and returns its ID.
func (s *Store) AddAlertRule(ctx context.Context, r AlertRule) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO alert_rules (network_id, kind, node, window_, baseline, mode, threshold, webhook)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		r.NetworkID, r.Kind, r.Node, r.Window, r.Baseline, r.Mode, r.Threshold, r.Webhook).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return id, nil
}

// AlertRules returns the rules of a network, by ID.
func (s *Store) AlertRules(ctx context.Context, networkID int64) ([]AlertRule, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, network_id, kind, node, window_, baseline, mode, threshold, webhook
		FROM alert_rules WHERE network_id = $1 ORDER BY id`, networkID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (AlertRule, error) {
		var a AlertRule
		err := r.Scan(&a.ID, &a.NetworkID, &a.Kind, &a.Node, &a.Window, &a.Baseline, &a.Mode, &a.Threshold, &a.Webhook)
		return a, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return out, nil
}

// SetAlert records the state of a rule and returns the state before
// ("" for a rule never evaluated); the change time moves only when the
// state changes.
func (s *Store) SetAlert(ctx context.Context, ruleID int64, state string, recent, baseline float64) (before string, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT state FROM alerts WHERE rule_id = $1 FOR UPDATE`, ruleID).Scan(&before)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO alerts (rule_id, state, recent, baseline) VALUES ($1, $2, $3, $4)
			ON CONFLICT (rule_id) DO UPDATE SET state = EXCLUDED.state, recent = EXCLUDED.recent, baseline = EXCLUDED.baseline,
			changed_at = CASE WHEN alerts.state = EXCLUDED.state THEN alerts.changed_at ELSE now() END`,
			ruleID, state, recent, baseline)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	return before, nil
}
