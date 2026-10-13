package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type ReexecList struct {
	Runs []store.ReexecRun `json:"runs"`
}
type ReexecPage struct {
	Steps []reexec.Step `json:"steps"`
	Next  *int64        `json:"next"`
}

func (s *Server) reexecList(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "unexpected reexec list query")
		return
	}
	rows, err := s.Store.ReexecRuns(r.Context(), d.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, ReexecList{rows})
}
func (s *Server) lookupReexec(w http.ResponseWriter, r *http.Request) (store.ReexecRun, bool) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return store.ReexecRun{}, false
	}
	id, err := strconv.ParseInt(r.PathValue("reexec"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "invalid reexec ID")
		return store.ReexecRun{}, false
	}
	row, err := s.Store.ReexecRun(r.Context(), d.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "reexec run not found")
		return row, false
	}
	if err != nil {
		s.fail(w, r, err)
		return row, false
	}
	return row, true
}
func (s *Server) reexecSummary(w http.ResponseWriter, r *http.Request) {
	row, ok := s.lookupReexec(w, r)
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "unexpected reexec query")
		return
	}
	writeJSON(w, 200, row)
}
func (s *Server) reexecSteps(w http.ResponseWriter, r *http.Request) {
	row, ok := s.lookupReexec(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	for k, v := range q {
		if (k != "after" && k != "limit" && k != "class" && k != "height") || len(v) != 1 {
			writeError(w, 400, "invalid reexec steps query")
			return
		}
	}
	after := int64(0)
	limit := 500
	var err error
	if q.Has("after") {
		after, err = strconv.ParseInt(q.Get("after"), 10, 64)
		if err != nil || after < 0 {
			writeError(w, 400, "invalid source ordinal")
			return
		}
	}
	if q.Has("limit") {
		limit, err = strconv.Atoi(q.Get("limit"))
		if err != nil || limit < 1 || limit > 1000 {
			writeError(w, 400, "limit must be 1..1000")
			return
		}
	}
	class, height := q.Get("class"), q.Get("height")
	if class != "" && !reexecClass(class) || height != "" && !fullDecimal.MatchString(height) {
		writeError(w, 400, "invalid reexec filter")
		return
	}
	rows, err := s.Store.ReexecSteps(r.Context(), row.ID, after, class, height, limit+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	result := ReexecPage{Steps: rows}
	if len(rows) > limit {
		n := rows[limit-1].Ordinal
		result.Next = &n
		result.Steps = rows[:limit]
	}
	writeJSON(w, 200, result)
}

func reexecClass(s string) bool {
	switch s {
	case "match", "output_diverged", "env_mismatch", "env_exhausted", "input_gap", "not_comparable", "warmup_suspect":
		return true
	default:
		return false
	}
}
