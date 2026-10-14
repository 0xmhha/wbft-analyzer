package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func (s *Server) buildSource(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	input := r.PathValue("input")
	line, err := strconv.ParseInt(r.PathValue("line"), 10, 64)
	if !logs.Identifier(input) || err != nil || line < 1 {
		writeError(w, 400, "invalid input ID or line")
		return
	}
	out, err := s.Store.BuildSource(r.Context(), d.ID, input, line)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "event source is not in this run dataset")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}
