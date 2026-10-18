package api

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/store"
)

var reconstructionRunID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

type ReconstructionList struct {
	Runs []store.ReconstructionRun `json:"runs"`
}
type ReconstructionPage struct {
	Steps []store.ReconstructionStep `json:"steps"`
	Next  *int64                     `json:"next"`
}

func (s *Server) reconstructionList(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected reconstruction query")
		return
	}
	rows, err := s.Store.ReconstructionRuns(r.Context(), d.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, ReconstructionList{Runs: rows})
}
func (s *Server) lookupReconstruction(w http.ResponseWriter, r *http.Request) (store.ReconstructionDetail, bool) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return store.ReconstructionDetail{}, false
	}
	id, err := strconv.ParseInt(r.PathValue("reconstruction"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "invalid reconstruction ID")
		return store.ReconstructionDetail{}, false
	}
	row, err := s.Store.ReconstructionRun(r.Context(), d.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "reconstruction not found")
		return row, false
	}
	if err != nil {
		s.fail(w, r, err)
		return row, false
	}
	return row, true
}
func (s *Server) reconstructionSummary(w http.ResponseWriter, r *http.Request) {
	row, ok := s.lookupReconstruction(w, r)
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected reconstruction query")
		return
	}
	writeJSON(w, 200, row)
}
func (s *Server) reconstructionSteps(w http.ResponseWriter, r *http.Request) {
	row, ok := s.lookupReconstruction(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	for k, v := range q {
		if (k != "after" && k != "limit" && k != "height" && k != "run" && k != "different") || len(v) != 1 {
			writeError(w, 400, "invalid reconstruction step query")
			return
		}
	}
	after, limit := int64(0), 50
	var err error
	if q.Has("after") {
		after, err = strconv.ParseInt(q.Get("after"), 10, 64)
		if err != nil || after < 0 {
			writeError(w, 400, "invalid reconstruction position")
			return
		}
	}
	if q.Has("limit") {
		limit, err = strconv.Atoi(q.Get("limit"))
		if err != nil || limit < 1 || limit > 100 {
			writeError(w, 400, "limit must be 1..100")
			return
		}
	}
	height, run, different := q.Get("height"), q.Get("run"), q.Get("different")
	if height != "" && !fullDecimal.MatchString(height) || run != "" && !reconstructionRunID.MatchString(run) || q.Has("different") && different != "true" && different != "false" {
		writeError(w, 400, "invalid reconstruction filter")
		return
	}
	rows, err := s.Store.ReconstructionSteps(r.Context(), row.ID, after, height, run, different == "true", limit+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	page := ReconstructionPage{Steps: rows}
	if len(rows) > limit {
		next := rows[limit-1].Position
		page.Next = &next
		page.Steps = rows[:limit]
	}
	writeJSON(w, 200, page)
}

func reconstructionParams(steps bool) []param {
	params := append(runParams(), param{name: "reconstruction", in: "path", typ: "integer", format: "int64", required: true, doc: "immutable source reconstruction ID"})
	if steps {
		params = append(params, param{name: "after", in: "query", typ: "integer", format: "int64", doc: "storage page position, distinct from actual source and reconstructed ordinals"}, param{name: "limit", in: "query", typ: "integer", doc: "1..100, default 50"}, param{name: "height", in: "query", typ: "string", doc: "full decimal active height"}, param{name: "run", in: "query", typ: "string", doc: "exact log run identity"}, param{name: "different", in: "query", typ: "string", doc: "true selects difference candidates; false retains all steps"})
	}
	return params
}
