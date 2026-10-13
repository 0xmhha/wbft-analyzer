package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/derive/observation"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"net/http"
	"strconv"
)

type ObservationHeaderPage struct {
	Index store.ObservationHeaderIndex `json:"index"`
	Rows  []observation.Binding        `json:"rows"`
	Total int64                        `json:"total"`
	Next  *string                      `json:"next"`
}

func (s *Server) observationHeaderIndex(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "observations")
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "binding index does not accept filters")
		return
	}
	data, e := s.Store.ObservationHeaderIndex(r.Context(), d.ID)
	if errors.Is(e, store.ErrObservationHeaderIndex) {
		writeError(w, 409, e.Error())
		return
	}
	if e != nil {
		s.fail(w, r, e)
		return
	}
	writeJSON(w, 200, data)
}
func (s *Server) observationHeaderRows(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "observations")
	if !ok {
		return
	}
	q := r.URL.Query()
	allowed := map[string]bool{"from": true, "to": true, "kind": true, "status": true, "limit": true, "cursor": true}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			writeError(w, 400, "invalid binding filter")
			return
		}
	}
	f := store.ObservationHeaderFilter{From: q.Get("from"), To: q.Get("to"), Kind: q.Get("kind"), Status: q.Get("status")}
	if _, _, e := observe.Range(f.From, f.To); e != nil {
		writeError(w, 400, e.Error())
		return
	}
	if f.Kind != "" && !oneOf(f.Kind, "head", "copy", "participation") || f.Status != "" && !oneOf(f.Status, "matched", "different", "unknown") {
		writeError(w, 400, "invalid binding kind/status")
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
	info, e := s.Store.ObservationHeaderIndex(r.Context(), d.ID)
	if errors.Is(e, store.ErrObservationHeaderIndex) {
		writeError(w, 409, e.Error())
		return
	}
	if e != nil {
		s.fail(w, r, e)
		return
	}
	lo, hi, _ := observe.Range(info.From, info.To)
	a, b, _ := observe.Range(f.From, f.To)
	if a.Cmp(lo) < 0 || b.Cmp(hi) > 0 {
		writeError(w, 400, "query exceeds binding scope")
		return
	}
	sum := sha256.Sum256([]byte(info.Snapshot + ":" + r.PathValue("net") + ":" + r.PathValue("dataset") + ":" + f.From + ":" + f.To + ":" + f.Kind + ":" + f.Status))
	scope := hex.EncodeToString(sum[:])
	offset := 0
	if q.Has("cursor") {
		raw, e := base64.RawURLEncoding.DecodeString(q.Get("cursor"))
		var c phaseCursor
		if e != nil || len(raw) > 512 || json.Unmarshal(raw, &c) != nil || c.Scope != scope || c.Offset < 0 {
			writeError(w, 400, "binding cursor does not match snapshot and filters")
			return
		}
		offset = c.Offset
	}
	current, rows, total, e := s.Store.ObservationHeaderRows(r.Context(), d.ID, f, int64(offset), limit)
	if errors.Is(e, store.ErrObservationHeaderIndex) {
		writeError(w, 409, e.Error())
		return
	}
	if e != nil {
		s.fail(w, r, e)
		return
	}
	if current.Snapshot != info.Snapshot {
		writeError(w, 409, "binding changed during query")
		return
	}
	page := ObservationHeaderPage{Index: current, Rows: rows, Total: total}
	if len(rows) > limit {
		page.Rows = rows[:limit]
		raw, _ := json.Marshal(phaseCursor{scope, offset + limit})
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.Next = &next
	}
	writeJSON(w, 200, page)
}
func observationHeaderParams() []param {
	return append(observationParams(), param{name: "kind", in: "query", doc: "head, copy or participation", typ: "string"}, param{name: "status", in: "query", doc: "matched, different or unknown", typ: "string"})
}
