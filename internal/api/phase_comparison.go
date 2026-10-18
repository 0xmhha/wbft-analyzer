package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func (s *Server) phaseComparison(w http.ResponseWriter, r *http.Request) {
	network, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	allowed := map[string]bool{"datasets": true, "from": true, "to": true, "node": true, "metric": true, "cross_network": true}
	for key, values := range q {
		if !allowed[key] || len(values) != 1 {
			writeError(w, 400, "unknown or duplicate phase comparison parameter")
			return
		}
	}
	if q.Has("cross_network") && q.Get("cross_network") != "1" {
		writeError(w, 400, "cross_network must be an explicit 1")
		return
	}
	from, to, node, metric := q.Get("from"), q.Get("to"), q.Get("node"), q.Get("metric")
	if !fullDecimal.MatchString(from) || !fullDecimal.MatchString(to) || node != "" && !logs.Identifier(node) || metric == "" || !phaseMetric(metric) {
		writeError(w, 400, "choose a full-height range, one phase metric and an optional node")
		return
	}
	parts := strings.Split(q.Get("datasets"), ",")
	if len(parts) < 2 || len(parts) > 16 {
		writeError(w, 400, "choose 2..16 distinct completed run dataset IDs")
		return
	}
	ids := []int64{}
	seen := map[int64]bool{}
	for _, part := range parts {
		id, err := strconv.ParseInt(part, 10, 64)
		if err != nil || id < 1 || seen[id] || strconv.FormatInt(id, 10) != part {
			writeError(w, 400, "invalid or repeated dataset ID")
			return
		}
		ids = append(ids, id)
		seen[id] = true
	}
	result, err := s.Store.PhaseComparison(r.Context(), network.ID, ids, from, to, node, metric, q.Get("cross_network") == "1")
	if errors.Is(err, store.ErrBaseline) || errors.Is(err, store.ErrPhaseWindowTooLarge) {
		writeError(w, 400, err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, result)
}
