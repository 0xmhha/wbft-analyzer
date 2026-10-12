package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Network is a stored network with the number of its reports.
type Network struct {
	ID          int64
	ChainID     string
	GenesisHash string
	Name        string
	Visibility  string
	Reports     int64
}

const networkColumns = `n.id, n.chain_id, n.genesis_hash, n.name, n.visibility,
	(SELECT count(*) FROM reports r WHERE r.network_id = n.id)`

func scanNetwork(r pgx.CollectableRow) (Network, error) {
	var n Network
	err := r.Scan(&n.ID, &n.ChainID, &n.GenesisHash, &n.Name, &n.Visibility, &n.Reports)
	return n, err
}

// Networks returns the networks, by ID.
func (s *Store) Networks(ctx context.Context) ([]Network, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+networkColumns+` FROM networks n ORDER BY n.id`)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return collect(rows, scanNetwork)
}

// Network returns one network, or ErrNotFound.
func (s *Store) Network(ctx context.Context, id int64) (Network, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+networkColumns+` FROM networks n WHERE n.id = $1`, id)
	if err != nil {
		return Network{}, fmt.Errorf("store: %w", err)
	}
	return one(rows, scanNetwork)
}

// ReportInfo is a stored report without its results and observations.
type ReportInfo struct {
	ID               string
	NetworkID        *int64
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
	LoadedAt         time.Time
}

const reportColumns = `id, network_id, run_id, started_at, finished_at, inspector_version, inspector_commit,
	catalog_sha256, spec_commit, network, range_, summary, loaded_at`

func scanReport(r pgx.CollectableRow) (ReportInfo, error) {
	var x ReportInfo
	err := r.Scan(&x.ID, &x.NetworkID, &x.RunID, &x.StartedAt, &x.FinishedAt, &x.InspectorVersion, &x.InspectorCommit,
		&x.CatalogSHA256, &x.SpecCommit, &x.Network, &x.Range, &x.Summary, &x.LoadedAt)
	return x, err
}

// Reports returns the reports of a network (all reports when networkID is
// nil), by finish time and ID.
func (s *Store) Reports(ctx context.Context, networkID *int64) ([]ReportInfo, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+reportColumns+` FROM reports
		WHERE $1::bigint IS NULL OR network_id = $1 ORDER BY finished_at, id`, networkID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return collect(rows, scanReport)
}

// Report returns one report, or ErrNotFound.
func (s *Store) Report(ctx context.Context, id string) (ReportInfo, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+reportColumns+` FROM reports WHERE id = $1`, id)
	if err != nil {
		return ReportInfo{}, fmt.Errorf("store: %w", err)
	}
	return one(rows, scanReport)
}

// Results returns the results of a report, by requirement and node. A nil
// verdict or node does not filter; an empty node selects the results for
// the whole run.
func (s *Store) Results(ctx context.Context, reportID string, verdict, node *string) ([]Result, error) {
	rows, err := s.pool.Query(ctx, `SELECT requirement, node, verdict, coverage FROM results
		WHERE report_id = $1 AND ($2::text IS NULL OR verdict = $2) AND ($3::text IS NULL OR node = $3)
		ORDER BY requirement, node`, reportID, verdict, node)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return collect(rows, func(r pgx.CollectableRow) (Result, error) {
		var x Result
		err := r.Scan(&x.Requirement, &x.Node, &x.Verdict, &x.Coverage)
		return x, err
	})
}

// Observations returns the observations of a report, by ID.
func (s *Store) Observations(ctx context.Context, reportID string) ([]Observation, error) {
	rows, err := s.pool.Query(ctx, `SELECT obs_id, kind, imp, requirements, node, count, first_at, last_at FROM observations
		WHERE report_id = $1 ORDER BY obs_id`, reportID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return collect(rows, func(r pgx.CollectableRow) (Observation, error) {
		var o Observation
		err := r.Scan(&o.ID, &o.Kind, &o.Imp, &o.Requirements, &o.Node, &o.Count, &o.First, &o.Last)
		return o, err
	})
}

// ReplaceAlertRules makes rules the alert rules of a network. A stored rule
// equal to one of rules (all fields but the ID) is kept with its alert
// state; the others are deleted and the new ones added. It returns the
// rules of the network after the change.
func (s *Store) ReplaceAlertRules(ctx context.Context, networkID int64, rules []AlertRule) ([]AlertRule, error) {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Serialize replacements of the same network.
		if _, err := tx.Exec(ctx, `SELECT id FROM networks WHERE id = $1 FOR UPDATE`, networkID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id, network_id, kind, node, window_, baseline, mode, threshold, webhook
			FROM alert_rules WHERE network_id = $1`, networkID)
		if err != nil {
			return err
		}
		have, err := pgx.CollectRows(rows, scanAlertRule)
		if err != nil {
			return err
		}
		want := make([]AlertRule, len(rules))
		for i, r := range rules {
			r.ID, r.NetworkID = 0, networkID
			want[i] = r
		}
		for _, h := range have {
			id := h.ID
			h.ID = 0
			if i := indexRule(want, h); i >= 0 {
				want = append(want[:i], want[i+1:]...)
				continue
			}
			if _, err := tx.Exec(ctx, `DELETE FROM alert_rules WHERE id = $1`, id); err != nil {
				return err
			}
		}
		for _, r := range want {
			if _, err := tx.Exec(ctx, `INSERT INTO alert_rules (network_id, kind, node, window_, baseline, mode, threshold, webhook)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				networkID, r.Kind, r.Node, r.Window, r.Baseline, r.Mode, r.Threshold, r.Webhook); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return s.AlertRules(ctx, networkID)
}

func indexRule(rs []AlertRule, r AlertRule) int {
	for i, x := range rs {
		if x == r {
			return i
		}
	}
	return -1
}

func scanAlertRule(r pgx.CollectableRow) (AlertRule, error) {
	var a AlertRule
	err := r.Scan(&a.ID, &a.NetworkID, &a.Kind, &a.Node, &a.Window, &a.Baseline, &a.Mode, &a.Threshold, &a.Webhook)
	return a, err
}

// AlertState is the recorded state of an alert rule.
type AlertState struct {
	Rule      AlertRule
	State     string
	Recent    float64
	Baseline  float64
	ChangedAt time.Time
}

// Alerts returns the states of the evaluated rules of a network (of all
// networks when networkID is nil), by rule ID.
func (s *Store) Alerts(ctx context.Context, networkID *int64) ([]AlertState, error) {
	rows, err := s.pool.Query(ctx, `SELECT r.id, r.network_id, r.kind, r.node, r.window_, r.baseline, r.mode, r.threshold, r.webhook,
		a.state, a.recent, a.baseline, a.changed_at
		FROM alerts a JOIN alert_rules r ON r.id = a.rule_id
		WHERE $1::bigint IS NULL OR r.network_id = $1 ORDER BY r.id`, networkID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return collect(rows, func(r pgx.CollectableRow) (AlertState, error) {
		var a AlertState
		x := &a.Rule
		err := r.Scan(&x.ID, &x.NetworkID, &x.Kind, &x.Node, &x.Window, &x.Baseline, &x.Mode, &x.Threshold, &x.Webhook,
			&a.State, &a.Recent, &a.Baseline, &a.ChangedAt)
		return a, err
	})
}

func collect[T any](rows pgx.Rows, f pgx.RowToFunc[T]) ([]T, error) {
	out, err := pgx.CollectRows(rows, f)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return out, nil
}

func one[T any](rows pgx.Rows, f pgx.RowToFunc[T]) (T, error) {
	out, err := pgx.CollectExactlyOneRow(rows, f)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, fmt.Errorf("store: %w", err)
	}
	return out, nil
}
