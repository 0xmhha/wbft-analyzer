package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/scenariojob"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

type ScenarioSources struct {
	Enabled bool                     `json:"enabled"`
	Sources []scenariojob.SourceInfo `json:"sources"`
}
type ScenarioJobs struct {
	Jobs []store.ScenarioJob `json:"jobs"`
}
type ScenarioRuns struct {
	Runs []store.ScenarioRunInfo `json:"runs"`
}
type ScenarioRequest struct {
	Source string                 `json:"source_id"`
	Change scenario.NetworkChange `json:"change"`
}
type ScenarioSeedPage struct {
	Seeds []store.ScenarioSeed `json:"seeds"`
	Next  *int                 `json:"next"`
}

func (s *Server) scenarioSources(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "unexpected scenario query")
		return
	}
	sources := []scenariojob.SourceInfo{}
	if s.Scenarios != nil {
		sources = s.Scenarios.Sources(d.NetworkID, d.ID)
	}
	enabled := s.Scenarios != nil && s.Jobs != nil && s.Jobs.Available()
	writeJSON(w, 200, ScenarioSources{Enabled: enabled, Sources: sources})
}
func (s *Server) postScenarioJob(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if s.Scenarios == nil || s.Jobs == nil || !s.Jobs.Available() {
		writeError(w, 503, "scenario worker is not enabled")
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "unexpected scenario query")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, scenario.MaxChangeRequestBytes))
	var request ScenarioRequest
	if err != nil || whatif.DecodeJSONSize(raw, &request, scenario.MaxChangeRequestBytes) != nil {
		writeError(w, 400, "invalid scenario request")
		return
	}
	if _, _, err := request.Change.Canonical(); err != nil {
		writeError(w, 400, "unsupported network change")
		return
	}
	job, err := s.Scenarios.Enqueue(r.Context(), d.NetworkID, d.ID, request.Source, request.Change)
	switch {
	case errors.Is(err, scenariojob.ErrChange):
		writeError(w, 400, "network change exceeds registered model")
	case errors.Is(err, scenariojob.ErrSource):
		writeError(w, 422, "registered scenario model unavailable")
	case errors.Is(err, store.ErrReexecQueueFull):
		writeError(w, 429, "experiment queue is full")
	case errors.Is(err, store.ErrDatasetBusy), errors.Is(err, store.ErrDatasetDeleting):
		writeError(w, 409, "dataset is busy")
	case err != nil:
		s.fail(w, r, err)
	default:
		writeJSON(w, 202, job)
	}
}
func (s *Server) scenarioJobs(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "unexpected scenario query")
		return
	}
	jobs, err := s.Store.ScenarioJobs(r.Context(), d.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, ScenarioJobs{jobs})
}
func (s *Server) scenarioJob(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "unexpected scenario query")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("job"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "invalid scenario job ID")
		return
	}
	j, err := s.Store.ScenarioJob(r.Context(), d.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "scenario job not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, j)
}
func (s *Server) scenarioRuns(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "unexpected scenario query")
		return
	}
	runs, err := s.Store.ScenarioRuns(r.Context(), d.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, ScenarioRuns{runs})
}
func (s *Server) lookupScenario(w http.ResponseWriter, r *http.Request) (int64, int64, scenario.Experiment, bool) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return 0, 0, scenario.Experiment{}, false
	}
	id, err := strconv.ParseInt(r.PathValue("scenario"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "invalid scenario ID")
		return 0, 0, scenario.Experiment{}, false
	}
	e, err := s.Store.ScenarioRun(r.Context(), d.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "scenario not found")
		return 0, 0, e, false
	}
	if err != nil {
		s.fail(w, r, err)
		return 0, 0, e, false
	}
	return d.ID, id, e, true
}
func (s *Server) scenarioSummary(w http.ResponseWriter, r *http.Request) {
	_, id, e, ok := s.lookupScenario(w, r)
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "unexpected scenario query")
		return
	}
	writeJSON(w, 200, store.ScenarioRunInfo{ID: id, Summary: e, Credibility: e.Credibility()})
}
func (s *Server) scenarioSeeds(w http.ResponseWriter, r *http.Request) {
	dataset, id, _, ok := s.lookupScenario(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	for key, values := range q {
		if len(values) != 1 || key != "mode" && key != "after" && key != "limit" {
			writeError(w, 400, "invalid scenario page")
			return
		}
	}
	mode := q.Get("mode")
	if mode == "" {
		mode = "baseline"
	}
	after, limit := 0, 32
	var err error
	if v := q.Get("after"); v != "" {
		after, err = strconv.Atoi(v)
	}
	if err != nil || after < 0 || after > 128 {
		writeError(w, 400, "invalid scenario page")
		return
	}
	if v := q.Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
	}
	if err != nil || limit < 1 || limit > 128 || mode != "baseline" && mode != "counterfactual" {
		writeError(w, 400, "invalid scenario page")
		return
	}
	rows, err := s.Store.ScenarioSeeds(r.Context(), dataset, id, mode, after, limit+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var next *int
	if len(rows) > limit {
		v := rows[limit-1].Index
		next = &v
		rows = rows[:limit]
	}
	writeJSON(w, 200, ScenarioSeedPage{Seeds: rows, Next: next})
}

func (s *Server) scenarioComparison(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "unexpected scenario query")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("scenario"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "invalid scenario ID")
		return
	}
	plot, err := s.Store.ScenarioPlot(r.Context(), d.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "scenario not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, plot)
}
