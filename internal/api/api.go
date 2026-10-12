// Package api is the analyzer's REST API under /v1 (design.md 8.1): the
// networks, the inspector reports with their results and observations,
// the observation trends, and the alert rules and their states.
//
// Responses are JSON. Errors are {"error": "..."}; a store failure is
// logged and answered 500 without its detail.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/derive/trends"
	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

// DefaultMaxBody is the largest request body (a report) by default.
const DefaultMaxBody = 64 << 20

// Server serves the API.
type Server struct {
	Store    *store.Store
	Reporter *ingest.Reporter
	// Token is the bearer token every request must carry; empty serves
	// without authentication, to loopback host names only.
	Token string
	// MaxBody is the largest request body; 0 is DefaultMaxBody.
	MaxBody int64
	// Log receives the errors not shown to clients; nil is slog.Default.
	Log *slog.Logger
}

func (s *Server) maxBody() int64 {
	if s.MaxBody > 0 {
		return s.MaxBody
	}
	return DefaultMaxBody
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Handler returns the API handler: the routes of the route table
// (routes.go), behind the request checks (guard.go).
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	for _, rt := range routes {
		h := rt.handle
		m.HandleFunc(rt.method+" "+rt.path, func(w http.ResponseWriter, r *http.Request) { h(s, w, r) })
	}
	m.HandleFunc("GET "+openAPIPath, s.openAPI)
	m.HandleFunc("/v1/", func(w http.ResponseWriter, _ *http.Request) { writeError(w, http.StatusNotFound, "no such resource") })
	return s.guard(m)
}

// Network is a network: chain ID and genesis hash identify it.
type Network struct {
	ID          int64  `json:"id"`
	ChainID     string `json:"chain_id"`
	GenesisHash string `json:"genesis_hash"`
	Name        string `json:"name"`
	Visibility  string `json:"visibility" enum:"public,private"`
	Reports     int64  `json:"reports"`
}

func toNetwork(n store.Network) Network {
	return Network{ID: n.ID, ChainID: n.ChainID, GenesisHash: n.GenesisHash, Name: n.Name, Visibility: n.Visibility, Reports: n.Reports}
}

func (s *Server) networks(w http.ResponseWriter, r *http.Request) {
	ns, err := s.Store.Networks(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]Network, len(ns))
	for i, n := range ns {
		out[i] = toNetwork(n)
	}
	writeJSON(w, http.StatusOK, NetworkList{Networks: out})
}

func (s *Server) network(w http.ResponseWriter, r *http.Request) {
	n, ok := s.lookupNetwork(w, r)
	if ok {
		writeJSON(w, http.StatusOK, toNetwork(n))
	}
}

// lookupNetwork reads {net} and answers 400 or 404 when it is not a
// stored network.
func (s *Server) lookupNetwork(w http.ResponseWriter, r *http.Request) (store.Network, bool) {
	id, err := strconv.ParseInt(r.PathValue("net"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "the network is a positive integer ID")
		return store.Network{}, false
	}
	n, err := s.Store.Network(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such network")
		return n, false
	}
	if err != nil {
		s.fail(w, r, err)
		return n, false
	}
	return n, true
}

// netFilter reads the optional ?net= query parameter.
func netFilter(w http.ResponseWriter, r *http.Request) (*int64, bool) {
	q := r.URL.Query()
	if !q.Has("net") {
		return nil, true
	}
	id, err := strconv.ParseInt(q.Get("net"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "net is a positive integer ID")
		return nil, false
	}
	return &id, true
}

// NetworkList is the answer of GET /v1/networks.
type NetworkList struct {
	Networks []Network `json:"networks"`
}

// Report is a stored inspector report without its results and
// observations. Network, Range and Summary are the report's own sections.
type Report struct {
	ID               string          `json:"id"`
	NetworkID        *int64          `json:"network_id"`
	RunID            string          `json:"run_id"`
	StartedAt        string          `json:"started_at"`
	FinishedAt       string          `json:"finished_at"`
	InspectorVersion string          `json:"inspector_version"`
	InspectorCommit  string          `json:"inspector_commit"`
	CatalogSHA256    string          `json:"catalog_sha256"`
	SpecCommit       string          `json:"spec_commit"`
	Network          json.RawMessage `json:"network"`
	Range            json.RawMessage `json:"range"`
	Summary          json.RawMessage `json:"summary"`
	LoadedAt         time.Time       `json:"loaded_at"`
}

func toReport(x store.ReportInfo) Report {
	return Report{ID: x.ID, NetworkID: x.NetworkID, RunID: x.RunID, StartedAt: x.StartedAt, FinishedAt: x.FinishedAt,
		InspectorVersion: x.InspectorVersion, InspectorCommit: x.InspectorCommit, CatalogSHA256: x.CatalogSHA256,
		SpecCommit: x.SpecCommit, Network: orNull(x.Network), Range: orNull(x.Range), Summary: orNull(x.Summary), LoadedAt: x.LoadedAt}
}

func orNull(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return b
}

func (s *Server) reports(w http.ResponseWriter, r *http.Request) {
	net, ok := netFilter(w, r)
	if !ok {
		return
	}
	xs, err := s.Store.Reports(r.Context(), net)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]Report, len(xs))
	for i, x := range xs {
		out[i] = toReport(x)
	}
	writeJSON(w, http.StatusOK, ReportList{Reports: out})
}

var reportID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// lookupReport reads {id} and answers 400 or 404 when it is not a stored
// report.
func (s *Server) lookupReport(w http.ResponseWriter, r *http.Request) (store.ReportInfo, bool) {
	id := r.PathValue("id")
	if !reportID.MatchString(id) {
		writeError(w, http.StatusBadRequest, "a report ID is the lowercase hex sha256 of the report file")
		return store.ReportInfo{}, false
	}
	x, err := s.Store.Report(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such report")
		return x, false
	}
	if err != nil {
		s.fail(w, r, err)
		return x, false
	}
	return x, true
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	if x, ok := s.lookupReport(w, r); ok {
		writeJSON(w, http.StatusOK, toReport(x))
	}
}

// ReportList is the answer of GET /v1/reports.
type ReportList struct {
	Reports []Report `json:"reports"`
}

// Result is the verdict of one requirement; Node is empty for the whole
// run.
type Result struct {
	Requirement string          `json:"requirement"`
	Node        string          `json:"node"`
	Verdict     string          `json:"verdict"`
	Coverage    json.RawMessage `json:"coverage"`
}

func (s *Server) results(w http.ResponseWriter, r *http.Request) {
	x, ok := s.lookupReport(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	var verdict, node *string
	if q.Has("verdict") {
		v := q.Get("verdict")
		verdict = &v
	}
	if q.Has("node") {
		v := q.Get("node")
		node = &v
	}
	rs, err := s.Store.Results(r.Context(), x.ID, verdict, node)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]Result, len(rs))
	for i, y := range rs {
		out[i] = Result{Requirement: y.Requirement, Node: y.Node, Verdict: y.Verdict, Coverage: orNull(y.Coverage)}
	}
	writeJSON(w, http.StatusOK, ResultList{Results: out})
}

// ResultList is the answer of GET /v1/reports/{id}/results.
type ResultList struct {
	Results []Result `json:"results"`
}

// Observation is a finding of a report that is not a verdict. Imp holds
// improvement IDs only.
type Observation struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Imp          []string `json:"imp"`
	Requirements []string `json:"requirements"`
	Node         string   `json:"node"`
	Count        int64    `json:"count"`
	First        string   `json:"first"`
	Last         string   `json:"last"`
}

func (s *Server) observations(w http.ResponseWriter, r *http.Request) {
	x, ok := s.lookupReport(w, r)
	if !ok {
		return
	}
	obs, err := s.Store.Observations(r.Context(), x.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]Observation, len(obs))
	for i, o := range obs {
		out[i] = Observation{ID: o.ID, Kind: o.Kind, Imp: o.Imp, Requirements: o.Requirements, Node: o.Node, Count: o.Count,
			First: o.First, Last: o.Last}
	}
	writeJSON(w, http.StatusOK, ObservationList{Observations: out})
}

// ObservationList is the answer of GET /v1/reports/{id}/observations.
type ObservationList struct {
	Observations []Observation `json:"observations"`
}

// LoadResult is the outcome of a posted report: added, skipped (already
// stored), refused (not admitted by the public build) or invalid; Alerts
// are the rule states it changed.
type LoadResult struct {
	ID      string         `json:"id,omitempty"`
	Outcome ingest.Outcome `json:"outcome" enum:"added,skipped,refused,invalid"`
	Detail  string         `json:"detail"`
	Alerts  []ingest.Alert `json:"alerts"`
}

// postReport loads a report given as the request body with the loader of
// "ingest reports": 201 added, 200 skipped, 422 refused or invalid.
func (s *Server) postReport(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("the report is larger than %d bytes", tooBig.Limit))
			return
		}
		writeError(w, http.StatusBadRequest, "the body could not be read")
		return
	}
	res, err := s.Reporter.Load(r.Context(), "request", raw)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := LoadResult{ID: res.ID, Outcome: res.Outcome, Detail: res.Detail, Alerts: res.Alerts}
	if out.Alerts == nil {
		out.Alerts = []ingest.Alert{}
	}
	code := http.StatusOK
	switch res.Outcome {
	case ingest.Added:
		code = http.StatusCreated
	case ingest.Refused, ingest.Invalid:
		code = http.StatusUnprocessableEntity
	}
	writeJSON(w, code, out)
}

// TrendPoint is the rate of an observation kind in one report: count over
// the heights of the report's range. At is the report's finish time.
type TrendPoint struct {
	Report string  `json:"report"`
	At     string  `json:"at"`
	Kind   string  `json:"kind"`
	Node   string  `json:"node"`
	Rate   float64 `json:"rate"`
}

// trendPoints answers the points of one kind (and node; absent for the
// rate over all nodes) between from_t and to_t, both required (RFC 3339):
// there is no default window (design.md 8.1).
func (s *Server) trendPoints(w http.ResponseWriter, r *http.Request) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	kind, from, to := q.Get("kind"), q.Get("from_t"), q.Get("to_t")
	if kind == "" || from == "" || to == "" {
		writeError(w, http.StatusBadRequest, "kind, from_t and to_t are required")
		return
	}
	for _, t := range []string{from, to} {
		if _, err := time.Parse(time.RFC3339Nano, t); err != nil {
			writeError(w, http.StatusBadRequest, "from_t and to_t are RFC 3339 times")
			return
		}
	}
	ps, err := s.Store.SeriesBetween(r.Context(), n.ID, kind, q.Get("node"), from, to)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]TrendPoint, len(ps))
	for i, p := range ps {
		out[i] = TrendPoint{Report: p.Report, At: p.At, Kind: p.Kind, Node: p.Node, Rate: p.Rate}
	}
	writeJSON(w, http.StatusOK, TrendPointList{Points: out})
}

// TrendPointList is the answer of GET /v1/networks/{net}/trends/observations.
type TrendPointList struct {
	Points []TrendPoint `json:"points"`
}

// AlertRule is an alert rule of a network (design.md 6.7): the median of
// the last Window points of a kind (and node, empty for all nodes) above
// Threshold (absolute) or above Threshold times the median of the Baseline
// points before them (relative). Webhook, if set, is told of state
// changes.
type AlertRule struct {
	ID        int64   `json:"id,omitempty"`
	Kind      string  `json:"kind"`
	Node      string  `json:"node"`
	Window    int     `json:"window"`
	Baseline  int     `json:"baseline"`
	Mode      string  `json:"mode" enum:"absolute,relative"`
	Threshold float64 `json:"threshold"`
	Webhook   string  `json:"webhook"`
}

func toAlertRule(a store.AlertRule) AlertRule {
	return AlertRule{ID: a.ID, Kind: a.Kind, Node: a.Node, Window: a.Window, Baseline: a.Baseline, Mode: a.Mode,
		Threshold: a.Threshold, Webhook: a.Webhook}
}

func (s *Server) alertRules(w http.ResponseWriter, r *http.Request) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	rs, err := s.Store.AlertRules(r.Context(), n.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeRules(w, rs)
}

func writeRules(w http.ResponseWriter, rs []store.AlertRule) {
	out := make([]AlertRule, len(rs))
	for i, a := range rs {
		out[i] = toAlertRule(a)
	}
	writeJSON(w, http.StatusOK, AlertRuleList{Rules: out})
}

// putAlertRules replaces the rules of a network with {"rules": [...]}. A
// rule equal to a stored one keeps its ID and alert state; the IDs in the
// body are ignored.
func (s *Server) putAlertRules(w http.ResponseWriter, r *http.Request) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	var body AlertRuleList
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil || d.More() || body.Rules == nil {
		writeError(w, http.StatusBadRequest, `the body is {"rules": [...]}`)
		return
	}
	rules := make([]store.AlertRule, len(body.Rules))
	for i, a := range body.Rules {
		tr := trends.Rule{Kind: a.Kind, Node: a.Node, Window: a.Window, Baseline: a.Baseline, Mode: trends.Mode(a.Mode), Threshold: a.Threshold}
		if err := tr.Check(); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("rules[%d]: %v", i, err))
			return
		}
		if a.Baseline < 0 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("rules[%d]: the baseline is negative", i))
			return
		}
		if err := checkWebhook(a.Webhook); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("rules[%d]: %v", i, err))
			return
		}
		rules[i] = store.AlertRule{Kind: a.Kind, Node: a.Node, Window: a.Window, Baseline: a.Baseline, Mode: a.Mode,
			Threshold: a.Threshold, Webhook: a.Webhook}
	}
	rs, err := s.Store.ReplaceAlertRules(r.Context(), n.ID, rules)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeRules(w, rs)
}

func checkWebhook(u string) error {
	if u == "" {
		return nil
	}
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" || p.User != nil {
		return errors.New("the webhook is an http or https URL without credentials")
	}
	return nil
}

// AlertRuleList is the rules of a network: the answer of GET and the body
// and answer of PUT /v1/networks/{net}/alert-rules.
type AlertRuleList struct {
	Rules []AlertRule `json:"rules"`
}

// Alert is the recorded state of an evaluated rule.
type Alert struct {
	Rule      AlertRule `json:"rule"`
	NetworkID int64     `json:"network_id"`
	State     string    `json:"state" enum:"pending,firing,resolved"`
	Recent    float64   `json:"recent"`
	Baseline  float64   `json:"baseline"`
	ChangedAt time.Time `json:"changed_at"`
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	net, ok := netFilter(w, r)
	if !ok {
		return
	}
	as, err := s.Store.Alerts(r.Context(), net)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]Alert, len(as))
	for i, a := range as {
		out[i] = Alert{Rule: toAlertRule(a.Rule), NetworkID: a.Rule.NetworkID, State: a.State, Recent: a.Recent, Baseline: a.Baseline,
			ChangedAt: a.ChangedAt}
	}
	writeJSON(w, http.StatusOK, AlertList{Alerts: out})
}

// AlertList is the answer of GET /v1/alerts.
type AlertList struct {
	Alerts []Alert `json:"alerts"`
}

// Error is the answer to a request that failed.
type Error struct {
	Error string `json:"error"`
}

// fail logs an internal error and answers 500 without its detail. A
// request the client gave up on is not logged.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	if !errors.Is(r.Context().Err(), context.Canceled) {
		s.log().Error("api", "method", r.Method, "path", r.URL.Path, "err", err)
	}
	writeError(w, http.StatusInternalServerError, "internal error")
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, Error{Error: msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
