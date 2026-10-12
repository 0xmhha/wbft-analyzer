package api

import (
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) roundBaseline(w http.ResponseWriter, r *http.Request) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	for _, v := range q {
		if len(v) != 1 {
			writeError(w, 400, "duplicate baseline parameter")
			return
		}
	}
	from, to, node := q.Get("from"), q.Get("to"), q.Get("node")
	if !fullDecimal.MatchString(from) || !fullDecimal.MatchString(to) || node != "" && !logs.Identifier(node) {
		writeError(w, 400, "from/to full height and optional node are required")
		return
	}
	parts := strings.Split(q.Get("datasets"), ",")
	if len(parts) < 2 || len(parts) > 16 {
		writeError(w, 400, "choose 2..16 distinct completed run dataset IDs")
		return
	}
	ids := []int64{}
	seen := map[int64]bool{}
	for _, p := range parts {
		id, err := strconv.ParseInt(p, 10, 64)
		if err != nil || id < 1 || seen[id] {
			writeError(w, 400, "invalid or repeated dataset ID")
			return
		}
		seen[id] = true
		ids = append(ids, id)
	}
	out, err := s.Store.RoundBaseline(r.Context(), n.ID, ids, from, to, node)
	if errors.Is(err, store.ErrBaseline) {
		writeError(w, 400, err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}
