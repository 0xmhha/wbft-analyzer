package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/reconstruct"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func (s *Server) reconstructionReview(w http.ResponseWriter, r *http.Request) {
	row, ok := s.lookupReconstruction(w, r)
	if !ok {
		return
	}
	position, err := strconv.ParseInt(r.PathValue("position"), 10, 64)
	if err != nil || position < 1 || len(r.URL.Query()) != 0 {
		writeError(w, 400, "positive reconstruction position and no query required")
		return
	}
	packet, err := s.Store.ReconstructionReview(r.Context(), row.Dataset, row.ID, position)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "reconstructed step not found")
	case errors.Is(err, reconstruct.ErrReview):
		writeError(w, 409, "reconstructed review source metadata unavailable")
	case err != nil:
		s.fail(w, r, err)
	default:
		writeJSON(w, 200, packet)
	}
}
