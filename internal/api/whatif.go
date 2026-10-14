package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

type WhatifList struct {
	Runs []store.WhatifRun `json:"runs"`
}
type WhatifPage struct {
	Steps []whatif.Step `json:"steps"`
	Next  *int64        `json:"next"`
}

func (s *Server) whatifList(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected experiment query")
		return
	}
	runs, err := s.Store.WhatifRuns(r.Context(), d.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, WhatifList{runs})
}
func (s *Server) lookupWhatif(w http.ResponseWriter, r *http.Request) (store.WhatifRun, bool) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return store.WhatifRun{}, false
	}
	id, err := strconv.ParseInt(r.PathValue("whatif"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "invalid experiment ID")
		return store.WhatifRun{}, false
	}
	run, err := s.Store.WhatifRun(r.Context(), d.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "experiment not found")
		return run, false
	}
	if err != nil {
		s.fail(w, r, err)
		return run, false
	}
	return run, true
}
func (s *Server) whatifSummary(w http.ResponseWriter, r *http.Request) {
	run, ok := s.lookupWhatif(w, r)
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected experiment query")
		return
	}
	writeJSON(w, 200, run)
}
func (s *Server) whatifSteps(w http.ResponseWriter, r *http.Request) {
	run, ok := s.lookupWhatif(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	after := int64(0)
	limit := 100
	for key, value := range q {
		if len(value) != 1 || key != "after" && key != "limit" {
			writeError(w, 400, "invalid experiment page")
			return
		}
	}
	if value := q.Get("after"); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			writeError(w, 400, "invalid execution cursor")
			return
		}
		after = n
	}
	if value := q.Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, 400, "invalid page limit")
			return
		}
		limit = n
	}
	rows, err := s.Store.WhatifResults(r.Context(), run.ID, after, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var next *int64
	if len(rows) == limit {
		n, err := strconv.ParseInt(rows[len(rows)-1].Execution, 10, 64)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		next = &n
	}
	writeJSON(w, 200, WhatifPage{rows, next})
}
func whatifParams(page bool) []param {
	out := append(runParams(), param{name: "whatif", in: "path", typ: "integer", format: "int64", required: true, doc: "counterfactual experiment ID"})
	if page {
		out = append(out, param{name: "after", in: "query", typ: "integer", format: "int64", doc: "last execution step"}, param{name: "limit", in: "query", typ: "integer", doc: "page limit, 1..1000"})
	}
	return out
}
