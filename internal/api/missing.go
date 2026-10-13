package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/derive/missing"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type MissingPage struct {
	Index store.MissingIndex `json:"index"`
	Cells []missing.Cell     `json:"cells"`
	Total int64              `json:"total"`
	Next  *string            `json:"next"`
}

func (s *Server) missingCells(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	allowed := map[string]bool{"from": true, "to": true, "validator": true, "phase": true, "class": true, "reason": true, "limit": true, "cursor": true}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			writeError(w, 400, "invalid missing query")
			return
		}
	}
	from, to, ok := headerRange(w, r, 1024)
	if !ok {
		return
	}
	f := store.MissingFilter{From: from, To: to, Validator: strings.ToLower(q.Get("validator")), Phase: q.Get("phase"), Class: q.Get("class"), Reason: q.Get("reason")}
	if f.Phase != "" && !oneOf(f.Phase, "PREPARE", "COMMIT") || f.Class != "" && !oneOf(f.Class, "SEALED", "SENT_ACCEPTED_NOT_SEALED", "SENT_REJECTED", "SENT_UNSEEN", "NOT_SENT", "UNKNOWN") {
		writeError(w, 400, "invalid missing classification filter")
		return
	}
	if f.Validator != "" {
		_, e := hex.DecodeString(strings.TrimPrefix(f.Validator, "0x"))
		if len(f.Validator) != 42 || !strings.HasPrefix(f.Validator, "0x") || e != nil {
			writeError(w, 400, "validator must be an address")
			return
		}
	}
	if len(f.Reason) > 128 {
		writeError(w, 400, "invalid reason")
		return
	}
	limit := 100
	if q.Has("limit") {
		n, e := strconv.Atoi(q.Get("limit"))
		if e != nil || n < 1 || n > 1000 {
			writeError(w, 400, "limit must be 1..1000")
			return
		}
		limit = n
	}
	var c phaseCursor
	if q.Has("cursor") {
		raw, e := base64.RawURLEncoding.DecodeString(q.Get("cursor"))
		if e != nil || len(raw) > 512 || json.Unmarshal(raw, &c) != nil || c.Offset < 0 || c.Scope == "" {
			writeError(w, 400, "invalid missing cursor")
			return
		}
	}
	index, cells, total, e := s.Store.MissingData(r.Context(), d.ID, f, int64(c.Offset), limit)
	if errors.Is(e, store.ErrMissingIndex) {
		writeError(w, 409, e.Error())
		return
	}
	if errors.Is(e, store.ErrMissingScope) {
		writeError(w, 400, e.Error())
		return
	}
	if e != nil {
		s.fail(w, r, e)
		return
	}
	params := r.URL.Query()
	params.Del("cursor")
	params.Del("limit")
	hash := sha256.Sum256([]byte(index.Snapshot + ":" + r.PathValue("net") + ":" + r.PathValue("dataset") + ":" + params.Encode()))
	scope := hex.EncodeToString(hash[:])
	if q.Has("cursor") && c.Scope != scope {
		writeError(w, 400, "missing cursor does not match snapshot and filters")
		return
	}
	page := MissingPage{Index: index, Cells: cells, Total: total}
	if len(cells) > limit {
		page.Cells = cells[:limit]
		raw, _ := json.Marshal(phaseCursor{scope, c.Offset + limit})
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.Next = &next
	}
	writeJSON(w, 200, page)
}
func missingParams() []param {
	return append(append(runParams(), headerParams()[1:]...), param{name: "validator", in: "query", doc: "one validator address", typ: "string"}, param{name: "phase", in: "query", doc: "PREPARE or COMMIT", typ: "string"}, param{name: "class", in: "query", doc: "one missing classification", typ: "string"}, param{name: "reason", in: "query", doc: "one evidence reason", typ: "string"}, param{name: "limit", in: "query", doc: "page size 1..1000", typ: "integer"}, param{name: "cursor", in: "query", doc: "snapshot and filter-bound cursor", typ: "string"})
}

func (s *Server) missingIndex(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	if len(r.URL.Query()) > 0 {
		writeError(w, 400, "missing index does not accept query filters")
		return
	}
	index, e := s.Store.MissingIndex(r.Context(), d.ID)
	if errors.Is(e, store.ErrMissingIndex) {
		writeError(w, 409, e.Error())
		return
	}
	if e != nil {
		s.fail(w, r, e)
		return
	}
	writeJSON(w, 200, index)
}
