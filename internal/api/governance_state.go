package api

import (
	"errors"
	"net/http"

	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func (s *Server) governanceStateWitnesses(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "governance")
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "execution-state evidence does not accept query filters")
		return
	}
	result, err := s.Store.GovernanceStateEvidence(r.Context(), d.ID, r.PathValue("index"))
	if errors.Is(err, store.ErrGovernanceQuery) {
		writeError(w, 400, "one canonical decimal uint64 index is required")
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 409, "governance capture is not ready")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, result)
}
