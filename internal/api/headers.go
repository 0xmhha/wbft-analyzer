package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type DatasetList struct {
	Datasets []store.Dataset `json:"datasets"`
}
type HeaderList struct {
	Headers []headers.Row `json:"headers"`
}
type EpochList struct {
	Epochs []store.Epoch `json:"epochs"`
}

func (s *Server) datasets(w http.ResponseWriter, r *http.Request) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	for key, values := range q {
		if key != "kind" || len(values) != 1 {
			writeError(w, 400, "one dataset kind filter is supported")
			return
		}
	}
	kind := q.Get("kind")
	if q.Has("kind") {
		switch kind {
		case "run", "range", "follow", "reports", "messages", "observations", "runtime":
		default:
			writeError(w, 400, "invalid dataset kind")
			return
		}
	}
	ds, err := s.Store.DatasetsByKind(r.Context(), n.ID, kind)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, DatasetList{ds})
}
func (s *Server) headerBounds(w http.ResponseWriter, r *http.Request) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	b, err := s.Store.HeaderBounds(r.Context(), n.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, b)
}
func headerRange(w http.ResponseWriter, r *http.Request, limit uint64) (uint64, uint64, bool) {
	a, e1 := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	b, e2 := strconv.ParseUint(r.URL.Query().Get("to"), 10, 64)
	if e1 != nil || e2 != nil || b < a || b-a >= limit {
		writeError(w, 400, "from/to must be decimal uint64 indices in an ordered bounded window")
		return 0, 0, false
	}
	return a, b, true
}
func copyFilter(w http.ResponseWriter, r *http.Request) (*int64, string, bool) {
	q := r.URL.Query()
	node := q.Get("node")
	if !q.Has("dataset") && node == "" {
		return nil, "", true
	}
	id, err := strconv.ParseInt(q.Get("dataset"), 10, 64)
	if err != nil || id < 1 || node == "" {
		writeError(w, 400, "dataset and node must be supplied together")
		return nil, "", false
	}
	return &id, node, true
}
func (s *Server) headers(w http.ResponseWriter, r *http.Request) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	a, b, ok := headerRange(w, r, 1024)
	if !ok {
		return
	}
	d, node, ok := copyFilter(w, r)
	if !ok {
		return
	}
	if d != nil {
		ds, err := s.Store.Datasets(r.Context(), n.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		found := false
		for _, x := range ds {
			if x.ID == *d {
				found = true
			}
		}
		if !found {
			writeError(w, 404, "dataset does not belong to this network")
			return
		}
	}
	rows, err := s.Store.HeaderRows(r.Context(), n.ID, strconv.FormatUint(a, 10), strconv.FormatUint(b, 10), d, node)
	if errors.Is(err, store.ErrObservationHeaderIndex) {
		writeError(w, 409, err.Error())
		return
	}

	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, HeaderList{rows})
}
func (s *Server) epochs(w http.ResponseWriter, r *http.Request) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	a, b, ok := headerRange(w, r, 1_000_000)
	if !ok {
		return
	}
	xs, err := s.Store.Epochs(r.Context(), n.ID, strconv.FormatUint(a, 10), strconv.FormatUint(b, 10))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, EpochList{xs})
}
func (s *Server) headerSummary(w http.ResponseWriter, r *http.Request) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	a, b, ok := headerRange(w, r, 100_000)
	if !ok {
		return
	}
	summary, err := s.Store.HeaderSummary(r.Context(), n.ID, a, b)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, summary)
}
