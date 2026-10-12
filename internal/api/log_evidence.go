package api

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func (s *Server) logEvidence(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	for _, values := range q {
		if len(values) != 1 {
			writeError(w, 400, "duplicate evidence query parameter")
			return
		}
	}
	rep, obs := q.Get("report"), q.Get("observation")
	index, err := strconv.Atoi(q.Get("index"))
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(rep) || obs == "" || len(obs) > 128 || err != nil || index < 0 || index >= 20 {
		writeError(w, 400, "report, observation and evidence index 0..19 are required")
		return
	}
	out, err := s.Store.ResolveLogEvidence(r.Context(), d.ID, rep, obs, index)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "report observation source pointer not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}
