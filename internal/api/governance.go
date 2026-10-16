package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type GovernancePage struct {
	Snapshot   string                  `json:"snapshot"`
	Call       store.GovernanceCall    `json:"call"`
	Collection string                  `json:"collection" enum:"operations,faults,states,proposals,changes,mirrors"`
	Rows       []store.GovernanceEntry `json:"rows"`
	Total      int64                   `json:"total"`
	Next       *string                 `json:"next"`
}

func (s *Server) governanceCapture(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "governance")
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "capture does not accept query filters")
		return
	}
	data, err := s.Store.GovernanceCapture(r.Context(), d.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 409, "governance capture is not ready")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, data)
}

func governanceOrdinal(r *http.Request) (int, bool) {
	raw := r.PathValue("ordinal")
	n, err := strconv.Atoi(raw)
	return n, err == nil && n > 0 && strconv.Itoa(n) == raw
}

func (s *Server) governanceCall(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "governance")
	if !ok {
		return
	}
	n, ok := governanceOrdinal(r)
	if !ok || len(r.URL.Query()) > 0 {
		writeError(w, 400, "one positive original request ordinal is required")
		return
	}
	if _, err := s.Store.GovernanceCapture(r.Context(), d.ID); errors.Is(err, store.ErrNotFound) {
		writeError(w, 409, "governance capture is not ready")
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	data, err := s.Store.GovernanceCall(r.Context(), d.ID, n)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "governance source request not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, data)
}

func (s *Server) governanceEntries(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "governance")
	if !ok {
		return
	}
	n, ok := governanceOrdinal(r)
	if !ok {
		writeError(w, 400, "one positive original request ordinal is required")
		return
	}
	q := r.URL.Query()
	for key, values := range q {
		if (key != "collection" && key != "limit" && key != "cursor") || len(values) != 1 {
			writeError(w, 400, "invalid governance page filter")
			return
		}
	}
	collection := q.Get("collection")
	limit := 100
	if q.Has("limit") {
		v, err := strconv.Atoi(q.Get("limit"))
		if err != nil || v < 1 || v > 500 {
			writeError(w, 400, "limit must be 1..500")
			return
		}
		limit = v
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
	if n > len(info.Calls) {
		writeError(w, 404, "governance source request not found")
		return
	}
	call := info.Calls[n-1]
	if call.Ordinal != n || !store.GovernanceCollection(call.Request.Method, collection) {
		writeError(w, 400, "collection does not match the original request scope")
		return
	}
	sum := sha256.Sum256([]byte(info.Snapshot + ":" + strconv.FormatInt(d.NetworkID, 10) + ":" + strconv.FormatInt(d.ID, 10) + ":" + strconv.Itoa(n) + ":" + collection))
	scope := hex.EncodeToString(sum[:])
	offset := 0
	if q.Has("cursor") {
		encoded := q.Get("cursor")
		if len(encoded) > 700 {
			writeError(w, 400, "invalid governance cursor")
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		var c phaseCursor
		if err != nil || jsonmeta.Decode(raw, 512, true, &c) != nil || c.Scope != scope || c.Offset < 0 {
			writeError(w, 400, "cursor does not match the governance source and collection")
			return
		}
		offset = c.Offset
	}
	rows, total, err := s.Store.GovernanceEntries(r.Context(), d.ID, n, collection, int64(offset), limit)
	if errors.Is(err, store.ErrGovernanceQuery) {
		writeError(w, 400, "invalid governance page scope or offset")
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
	page := GovernancePage{Snapshot: info.Snapshot, Call: call, Collection: collection, Rows: rows, Total: total}
	if len(rows) > limit {
		page.Rows = rows[:limit]
		raw, _ := json.Marshal(phaseCursor{scope, offset + limit})
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.Next = &next
	}
	writeJSON(w, 200, page)
}

func governanceCallParams() []param {
	return append(runParams(), param{name: "ordinal", in: "path", doc: "positive original request ordinal", typ: "integer", format: "int64", required: true})
}
func governanceEntryParams() []param {
	return append(governanceCallParams(), param{name: "collection", in: "query", doc: "operations, faults, states, proposals, changes or mirrors; must match the original RPC method", typ: "string", required: true}, param{name: "limit", in: "query", doc: "page size 1..500", typ: "integer"}, param{name: "cursor", in: "query", doc: "immutable capture, network, dataset, request and collection-bound cursor", typ: "string"})
}
