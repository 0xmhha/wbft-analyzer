package api

import (
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

type WhatifNetworkBindingPage struct {
	Bindings []store.WhatifNetworkBinding `json:"bindings"`
	Next     *int64                       `json:"next"`
}
type WhatifNetworkEffectPage struct {
	Effects []whatif.NetworkEffect `json:"effects"`
	Next    *int64                 `json:"next"`
}

func networkPageQuery(r *http.Request) (int64, int, error) {
	q := r.URL.Query()
	after := int64(0)
	limit := 200
	for key, values := range q {
		if len(values) != 1 || key != "after" && key != "limit" {
			return 0, 0, whatif.ErrEvidence
		}
	}
	if value := q.Get("after"); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			return 0, 0, whatif.ErrEvidence
		}
		after = n
	}
	if value := q.Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 1000 {
			return 0, 0, whatif.ErrEvidence
		}
		limit = n
	}
	return after, limit, nil
}
func networkEvidenceParams() []param {
	out := whatifParams(true)
	for index := range out {
		if out[index].name == "after" {
			out[index].doc = "last evidence row ID"
		}
	}
	return out
}

func (s *Server) whatifNetworkBindings(w http.ResponseWriter, r *http.Request) {
	run, ok := s.lookupWhatif(w, r)
	if !ok {
		return
	}
	after, limit, err := networkPageQuery(r)
	if err != nil {
		writeError(w, 400, "invalid network evidence window")
		return
	}
	rows, err := s.Store.WhatifNetworkBindings(r.Context(), run.ID, after, limit+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var next *int64
	if len(rows) > limit {
		n, _ := strconv.ParseInt(rows[limit-1].ID, 10, 64)
		next = &n
		rows = rows[:limit]
	}
	if rows == nil {
		rows = []store.WhatifNetworkBinding{}
	}
	writeJSON(w, 200, WhatifNetworkBindingPage{rows, next})
}
func (s *Server) whatifNetworkEffects(w http.ResponseWriter, r *http.Request) {
	run, ok := s.lookupWhatif(w, r)
	if !ok {
		return
	}
	after, limit, err := networkPageQuery(r)
	if err != nil {
		writeError(w, 400, "invalid network effect window")
		return
	}
	rows, err := s.Store.WhatifNetworkEffects(r.Context(), run.ID, after, limit+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var next *int64
	if len(rows) > limit {
		n, _ := strconv.ParseInt(rows[limit-1].ID, 10, 64)
		next = &n
		rows = rows[:limit]
	}
	if rows == nil {
		rows = []whatif.NetworkEffect{}
	}
	writeJSON(w, 200, WhatifNetworkEffectPage{rows, next})
}
