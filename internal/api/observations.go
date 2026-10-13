package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type ObservationPage struct {
	Snapshot string                 `json:"snapshot"`
	Rows     []store.ObservationRow `json:"rows"`
	Total    int64                  `json:"total"`
	Next     *string                `json:"next"`
}

func (s *Server) observationCapture(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "observations")
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "capture does not accept query filters")
		return
	}
	data, e := s.Store.ObservationCapture(r.Context(), d.ID)
	if errors.Is(e, store.ErrNotFound) {
		writeError(w, 409, "observation capture is not ready")
		return
	}
	if e != nil {
		s.fail(w, r, e)
		return
	}
	writeJSON(w, 200, data)
}
func (s *Server) observationCall(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "observations")
	if !ok {
		return
	}
	ordinal, e := strconv.ParseInt(r.PathValue("ordinal"), 10, 64)
	if e != nil || ordinal < 1 || len(r.URL.Query()) > 0 {
		writeError(w, 400, "one positive source ordinal is required")
		return
	}
	data, e := s.Store.ObservationCall(r.Context(), d.ID, ordinal)
	if errors.Is(e, store.ErrNotFound) {
		writeError(w, 404, "observation source not found")
		return
	}
	if e != nil {
		s.fail(w, r, e)
		return
	}
	writeJSON(w, 200, data)
}
func (s *Server) observationRows(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "observations")
	if !ok {
		return
	}
	q := r.URL.Query()
	allowed := map[string]bool{"from": true, "to": true, "limit": true, "cursor": true}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			writeError(w, 400, "invalid observation filter")
			return
		}
	}
	from, to := q.Get("from"), q.Get("to")
	if _, _, e := observe.Range(from, to); e != nil {
		writeError(w, 400, e.Error())
		return
	}
	limit := 100
	if q.Has("limit") {
		v, e := strconv.Atoi(q.Get("limit"))
		if e != nil || v < 1 || v > 1000 {
			writeError(w, 400, "limit must be 1..1000")
			return
		}
		limit = v
	}
	info, e := s.Store.ObservationCapture(r.Context(), d.ID)
	if errors.Is(e, store.ErrNotFound) {
		writeError(w, 409, "observation capture is not ready")
		return
	}
	if e != nil {
		s.fail(w, r, e)
		return
	}
	sum := sha256.Sum256([]byte(info.Snapshot + ":" + r.PathValue("net") + ":" + r.PathValue("dataset") + ":" + from + ":" + to))
	scope := hex.EncodeToString(sum[:])
	offset := 0
	if q.Has("cursor") {
		raw, e := base64.RawURLEncoding.DecodeString(q.Get("cursor"))
		var c phaseCursor
		if e != nil || len(raw) > 512 || json.Unmarshal(raw, &c) != nil || c.Scope != scope || c.Offset < 0 {
			writeError(w, 400, "observation cursor does not match source and range")
			return
		}
		offset = c.Offset
	}
	lo, hi, _ := observe.Range(info.From, info.To)
	a, b, _ := observe.Range(from, to)
	if a.Cmp(lo) < 0 || b.Cmp(hi) > 0 {
		writeError(w, 400, "query exceeds capture range")
		return
	}
	rows, total, e := s.Store.ObservationRows(r.Context(), d.ID, from, to, int64(offset), limit)
	if e != nil {
		s.fail(w, r, e)
		return
	}
	page := ObservationPage{Snapshot: info.Snapshot, Rows: rows, Total: total}
	if len(rows) > limit {
		page.Rows = rows[:limit]
		raw, _ := json.Marshal(phaseCursor{scope, offset + limit})
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.Next = &next
	}
	writeJSON(w, 200, page)
}
func observationParams() []param {
	return append(runParams(), param{name: "from", in: "query", doc: "first full decimal height, not a low64 index", typ: "string", required: true}, param{name: "to", in: "query", doc: "last full decimal height, at most 1024 heights", typ: "string", required: true}, param{name: "limit", in: "query", doc: "page size 1..1000", typ: "integer"}, param{name: "cursor", in: "query", doc: "immutable capture and range-bound cursor", typ: "string"})
}
