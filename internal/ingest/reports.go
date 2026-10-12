// Package ingest loads datasets into the store.
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/derive/trends"
	"github.com/0xmhha/wbft-analyzer/internal/reports"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

// Outcome is what happened to one report file.
type Outcome string

// The outcomes of a report file.
const (
	Added   Outcome = "added"
	Skipped Outcome = "skipped" // already stored
	Refused Outcome = "refused" // not admitted by the public build
	Invalid Outcome = "invalid" // not a report, or unreadable
)

// Result is the outcome of one report file, and the alerts whose state it
// changed.
type Result struct {
	File    string
	ID      string
	Outcome Outcome
	Detail  string
	Alerts  []Alert
}

// Alert is a change of an alert rule's state.
type Alert struct {
	Rule     int64   `json:"rule"`
	Network  int64   `json:"network"`
	Kind     string  `json:"kind"`
	Node     string  `json:"node,omitempty"`
	Before   string  `json:"before"`
	State    string  `json:"state"`
	Recent   float64 `json:"recent"`
	Baseline float64 `json:"baseline,omitempty"`
	// WebhookError is the failure of the rule's webhook, if any.
	WebhookError string `json:"webhook_error,omitempty"`
}

// Reporter loads inspector reports.
type Reporter struct {
	Store *store.Store
	// HTTP posts the webhooks; nil uses a client with a 10 s timeout.
	HTTP *http.Client
}

// Files loads report files in order. A file that is not a report, or that
// the public build refuses, is recorded and skipped; a store error stops
// the load.
func (r *Reporter) Files(ctx context.Context, files []string) ([]Result, error) {
	var out []Result
	for _, f := range files {
		res, err := r.file(ctx, f)
		if err != nil {
			return out, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *Reporter) file(ctx context.Context, file string) (Result, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return Result{File: file, Outcome: Invalid, Detail: err.Error()}, nil
	}
	return r.Load(ctx, file, raw)
}

// Load loads one report given as its file contents; name is recorded as
// the result's File. Like Files, it returns an error only for a store
// error.
func (r *Reporter) Load(ctx context.Context, name string, raw []byte) (Result, error) {
	res := Result{File: name}
	rep, err := reports.Parse(raw)
	if err != nil {
		res.Outcome, res.Detail = Invalid, err.Error()
		return res, nil
	}
	res.ID = rep.ID
	if err := reports.Admit(rep); err != nil {
		if errors.Is(err, reports.ErrRefused) {
			res.Outcome, res.Detail = Refused, err.Error()
			return res, nil
		}
		return res, err
	}
	row, err := toRow(rep)
	if err != nil {
		res.Outcome, res.Detail = Invalid, err.Error()
		return res, nil
	}
	added, nid, err := r.Store.PutReport(ctx, row)
	if err != nil {
		return res, err
	}
	if !added {
		res.Outcome, res.Detail = Skipped, "already stored"
		return res, nil
	}
	res.Outcome = Added
	res.Detail = fmt.Sprintf("%d results, %d observations, %d trend points", len(row.Results), len(row.Observations), len(row.Points))
	if nid != 0 {
		res.Alerts, err = r.evaluate(ctx, nid)
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// toRow converts a report to its store row: the network when the run names
// chain ID and genesis hash, and the trend points when it has a range.
func toRow(rep *reports.Report) (*store.Report, error) {
	row := &store.Report{Inputs: rep.Run.Inputs, ID: rep.ID, RunID: rep.Run.ID, StartedAt: rep.Run.StartedAt, FinishedAt: rep.Run.FinishedAt,
		InspectorVersion: rep.Run.Inspector.Version, InspectorCommit: rep.Run.Inspector.Commit,
		CatalogSHA256: rep.Run.Inspector.CatalogSHA256, SpecCommit: rep.Run.Spec.Commit,
		Network: rep.Run.Network, Range: rep.Run.Range, Summary: rep.Summary}
	for _, x := range rep.Results {
		row.Results = append(row.Results, store.Result{Requirement: x.Requirement, Node: x.Node, Verdict: x.Verdict, Coverage: x.Coverage})
	}
	var obs []trends.Observation
	for _, o := range rep.Observations {
		evidence := o.Evidence
		if evidence == nil {
			evidence = []reports.Evidence{}
		}
		ev, _ := json.Marshal(evidence)
		row.Observations = append(row.Observations, store.Observation{ID: o.ID, Kind: o.Kind, Imp: o.Imp, Requirements: o.Requirements,
			Node: o.Node, Count: o.Count, First: o.First, Last: o.Last, Evidence: ev})
		obs = append(obs, trends.Observation{Kind: o.Kind, Node: o.Node, Count: o.Count})
	}
	if len(rep.Run.Network) > 0 && string(rep.Run.Network) != "null" {
		var n struct {
			Name        string          `json:"name"`
			ChainID     json.RawMessage `json:"chain_id"`
			GenesisHash string          `json:"genesis_hash"`
		}
		if err := json.Unmarshal(rep.Run.Network, &n); err != nil {
			return nil, fmt.Errorf("run.network: %w", err)
		}
		if id := uintText(n.ChainID); id != "" && n.GenesisHash != "" {
			row.NetworkKey = &store.NetworkKey{ChainID: id, GenesisHash: n.GenesisHash, Name: n.Name}
		}
	}
	if len(rep.Run.Range) > 0 && string(rep.Run.Range) != "null" && len(obs) > 0 {
		var rg struct {
			From json.RawMessage `json:"from"`
			To   json.RawMessage `json:"to"`
		}
		if err := json.Unmarshal(rep.Run.Range, &rg); err != nil {
			return nil, fmt.Errorf("run.range: %w", err)
		}
		if from, to := uintText(rg.From), uintText(rg.To); from != "" && to != "" {
			ps, err := trends.Points(rep.ID, rep.Run.FinishedAt, from, to, obs)
			if err != nil {
				return nil, err
			}
			for _, p := range ps {
				row.Points = append(row.Points, store.TrendPoint{Report: p.Report, At: p.At, Kind: p.Kind, Node: p.Node, Rate: p.Rate})
			}
		}
	}
	return row, nil
}

// uintText returns a decimal integer written as a JSON number or string.
func uintText(raw json.RawMessage) string {
	s := string(bytes.Trim(raw, `"`))
	for _, c := range s {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return s
}

// evaluate applies the alert rules of a network to its trend points,
// records their states and posts the webhook of each rule whose state
// changed.
func (r *Reporter) evaluate(ctx context.Context, networkID int64) ([]Alert, error) {
	rules, err := r.Store.AlertRules(ctx, networkID)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, rule := range rules {
		series, err := r.Store.Series(ctx, networkID, rule.Kind, rule.Node)
		if err != nil {
			return nil, err
		}
		ps := make([]trends.Point, len(series))
		for i, p := range series {
			ps[i] = trends.Point{Report: p.Report, At: p.At, Kind: p.Kind, Node: p.Node, Rate: p.Rate}
		}
		tr := trends.Rule{Kind: rule.Kind, Node: rule.Node, Window: rule.Window, Baseline: rule.Baseline, Mode: trends.Mode(rule.Mode),
			Threshold: rule.Threshold}
		e, err := tr.Evaluate(ps)
		if err != nil {
			return nil, fmt.Errorf("ingest: rule %d: %w", rule.ID, err)
		}
		before, err := r.Store.SetAlert(ctx, rule.ID, string(e.State), e.Recent, e.Baseline)
		if err != nil {
			return nil, err
		}
		if before == string(e.State) {
			continue
		}
		a := Alert{Rule: rule.ID, Network: networkID, Kind: rule.Kind, Node: rule.Node, Before: before, State: string(e.State),
			Recent: e.Recent, Baseline: e.Baseline}
		if rule.Webhook != "" {
			if err := r.post(ctx, rule.Webhook, a); err != nil {
				a.WebhookError = err.Error()
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// post sends an alert change to a webhook as JSON.
func (r *Reporter) post(ctx context.Context, url string, a Alert) error {
	c := r.HTTP
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook answered %s", resp.Status)
	}
	return nil
}
