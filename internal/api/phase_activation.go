package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func (s *Server) phaseActivation(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "run")
	if !ok {
		return
	}
	q := r.URL.Query()
	allowed := map[string]bool{"capture": true, "key": true, "before": true, "after": true, "node": true, "metric": true}
	for key, values := range q {
		if !allowed[key] || len(values) != 1 {
			writeError(w, 400, "unknown or duplicate activation comparison parameter")
			return
		}
	}
	capture, err := strconv.ParseInt(q.Get("capture"), 10, 64)
	if err != nil || capture < 1 || strconv.FormatInt(capture, 10) != q.Get("capture") {
		writeError(w, 400, "choose a completed declaration capture")
		return
	}
	widths := [2]int{}
	for i, key := range []string{"before", "after"} {
		value, e := strconv.Atoi(q.Get(key))
		if e != nil || value < 1 || value > 100000 || strconv.Itoa(value) != q.Get(key) {
			writeError(w, 400, "before and after must be canonical positive counts up to 100000")
			return
		}
		widths[i] = value
	}
	key, node, metric := q.Get("key"), q.Get("node"), q.Get("metric")
	if key == "" || len(key) > 128 || node != "" && !logs.Identifier(node) || !phaseMetric(metric) || metric == "" {
		writeError(w, 400, "choose a reported rule key, one phase metric and an optional observer")
		return
	}
	result, err := s.Store.PhaseActivationComparison(r.Context(), d.NetworkID, d.ID, capture, key, widths[0], widths[1], node, metric)
	if errors.Is(err, store.ErrPhaseActivation) || errors.Is(err, store.ErrBaseline) || errors.Is(err, store.ErrPhaseWindowTooLarge) {
		writeError(w, 400, err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, result)
}
