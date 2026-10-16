package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func (s *Server) governanceHeaderContext(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "governance")
	if !ok {
		return
	}
	call, validCall := governanceOrdinal(r)
	raw := r.PathValue("entry")
	entry, err := strconv.Atoi(raw)
	q := r.URL.Query()
	collection := q.Get("collection")
	if !validCall || err != nil || entry < 1 || strconv.Itoa(entry) != raw || len(q) != 1 || len(q["collection"]) != 1 || collection != "operations" && collection != "changes" {
		writeError(w, 400, "one positive request and entry ordinal and operations or changes collection are required")
		return
	}
	capture, err := s.Store.GovernanceCapture(r.Context(), d.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 409, "governance capture is not ready")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if call > len(capture.Calls) {
		writeError(w, 404, "governance source request not found")
		return
	}
	result, err := s.Store.GovernanceHeaderContext(r.Context(), d.ID, call, entry, collection)
	if errors.Is(err, store.ErrGovernanceQuery) {
		writeError(w, 400, "collection does not match the original request scope")
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "governance source entry not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, result)
}

func governanceHeaderParams() []param {
	return append(governanceCallParams(), param{name: "entry", in: "path", doc: "positive original collection entry ordinal", typ: "integer", format: "int64", required: true}, param{name: "collection", in: "query", doc: "operations or changes; must match the original RPC method", typ: "string", required: true})
}
