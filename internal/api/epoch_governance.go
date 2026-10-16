package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type GovernanceSingleEntry struct {
	Snapshot   string                `json:"snapshot"`
	Collection string                `json:"collection" enum:"operations,faults,states,proposals,changes,mirrors"`
	Entry      store.GovernanceEntry `json:"entry"`
}

func (s *Server) headerGovernanceClaims(w http.ResponseWriter, r *http.Request) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	raw := r.PathValue("index")
	index, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || strconv.FormatUint(index, 10) != raw || len(r.URL.Query()) != 0 {
		writeError(w, 400, "one canonical decimal uint64 index and no query filters are required")
		return
	}
	result, err := s.Store.HeaderGovernanceClaims(r.Context(), n.ID, raw)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "canonical header not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, result)
}

func (s *Server) governanceSingleEntry(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "governance")
	if !ok {
		return
	}
	call, valid := governanceOrdinal(r)
	raw := r.PathValue("entry")
	entry, err := strconv.Atoi(raw)
	q := r.URL.Query()
	collection := q.Get("collection")
	if !valid || err != nil || entry < 1 || strconv.Itoa(entry) != raw || len(q) != 1 || len(q["collection"]) != 1 {
		writeError(w, 400, "one positive request and entry ordinal and collection are required")
		return
	}
	info, err := s.Store.GovernanceCapture(r.Context(), d.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 409, "governance capture is not ready")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if call > len(info.Calls) {
		writeError(w, 404, "governance source request not found")
		return
	}
	if !store.GovernanceCollection(info.Calls[call-1].Request.Method, collection) {
		writeError(w, 400, "collection does not match the original request scope")
		return
	}
	rows, _, err := s.Store.GovernanceEntries(r.Context(), d.ID, call, collection, int64(entry-1), 1)
	if errors.Is(err, store.ErrGovernanceQuery) || errors.Is(err, store.ErrNotFound) || err == nil && (len(rows) == 0 || rows[0].Ordinal != entry) {
		writeError(w, 404, "governance source entry not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, GovernanceSingleEntry{Snapshot: info.Snapshot, Collection: collection, Entry: rows[0]})
}

func governanceSingleEntryParams() []param {
	return append(governanceCallParams(), param{name: "entry", in: "path", doc: "positive original collection entry ordinal", typ: "integer", format: "int64", required: true}, param{name: "collection", in: "query", doc: "original request collection", typ: "string", required: true})
}
