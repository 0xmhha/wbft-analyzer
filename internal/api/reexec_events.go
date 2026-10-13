package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func (s *Server) reexecEvents(w http.ResponseWriter, r *http.Request) {
	row, ok := s.lookupReexec(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	for k, v := range q {
		if (k != "ordinal" && k != "event_dataset") || len(v) != 1 {
			writeError(w, 400, "invalid replay event query")
			return
		}
	}
	ordinal, e := strconv.ParseInt(q.Get("ordinal"), 10, 64)
	dataset, d := strconv.ParseInt(q.Get("event_dataset"), 10, 64)
	if e != nil || d != nil || ordinal < 1 || dataset < 1 {
		writeError(w, 400, "positive source ordinal and event dataset required")
		return
	}
	out, err := s.Store.ReexecEvents(r.Context(), row.Dataset, row.ID, ordinal, dataset)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "replay step not found")
		return
	}
	if errors.Is(err, store.ErrPairSource) {
		writeError(w, 400, "event association source limit exceeded")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}
