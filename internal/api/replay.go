package api

import (
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) replayError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrReplayIndex) {
		writeError(w, 409, err.Error())
	} else if errors.Is(err, store.ErrReplayWindow) {
		writeError(w, 400, err.Error())
	} else {
		s.fail(w, r, err)
	}
}
func (s *Server) replayWindow(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	f, ok := eventWindow(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	endInput := q.Get("to_input")
	endLine := int64(0)
	if q.Has("to_input") || q.Has("to_line") {
		var err error
		endLine, err = strconv.ParseInt(q.Get("to_line"), 10, 64)
		if !logs.Identifier(endInput) || err != nil || endLine < 1 {
			writeError(w, 400, "to_input/to_line must identify a source event at to_t")
			return
		}
		endpoint, err := s.Store.LogEvent(r.Context(), d.ID, endInput, endLine)
		if err != nil {
			writeError(w, 400, "replay endpoint is unavailable")
			return
		}
		at, err := time.Parse(time.RFC3339Nano, endpoint.Wall)
		if err != nil || !at.Equal(f.To) || f.Node != "" && f.Node != endpoint.Node {
			writeError(w, 400, "replay endpoint does not match to_t/node")
			return
		}
	}
	out, err := s.Store.ReplayWindow(r.Context(), d.ID, f.From, f.To, f.Node, endInput, endLine)
	if err != nil {
		s.replayError(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) replayKeyframe(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	for _, v := range q {
		if len(v) != 1 {
			writeError(w, 400, "duplicate replay parameter")
			return
		}
	}
	node := q.Get("node")
	at, err := time.Parse(time.RFC3339Nano, q.Get("t"))
	if !logs.Identifier(node) || err != nil {
		writeError(w, 400, "node and RFC3339 t are required")
		return
	}
	inputs, err := s.Store.LogInputs(r.Context(), d.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	found := false
	for _, in := range inputs {
		if in.Node == node {
			found = true
		}
	}
	if !found {
		writeError(w, 404, "node is absent from this dataset")
		return
	}
	out, err := s.Store.ReplayState(r.Context(), d.ID, node, at)
	if err != nil {
		s.replayError(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}
