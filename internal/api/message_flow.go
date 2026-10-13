package api

import (
	derived "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"net/http"
	"sort"
	"strconv"
)

type MessageFlow struct {
	Index store.PairIndex `json:"index"`
	Pairs []derived.Pair  `json:"pairs"`
	Nodes []string        `json:"nodes"`
	From  string          `json:"from_t"`
	To    string          `json:"to_t"`
}

// A flow overlays the explicit event execution only. Same-network names and
// overlapping wall windows are not sufficient to join two executions.
func (s *Server) messageFlow(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if !q.Has("from_t") || !q.Has("to_t") || q.Has("limit") || q.Has("cursor") || q.Has("threshold") {
		writeError(w, 400, "flow requires from_t/to_t and does not accept paging or threshold")
		return
	}
	events, e := strconv.ParseInt(q.Get("events"), 10, 64)
	if e != nil || events <= 0 {
		writeError(w, 400, "events must identify the overlay run dataset")
		return
	}
	index, pairs, _, ok := s.pairData(w, r, true)
	if !ok {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("dataset"), 10, 64)
	if events != id && (index.EventDataset != events || index.Association == nil || index.Association.Status != "matched") {
		writeError(w, 400, "flow requires a verified event companion for this execution")
		return
	}
	// When the evidence is the run itself, ordinary pairing source lookup has
	// already checked its network; a journal cannot masquerade as that run.
	overlay := r.Clone(r.Context())
	overlay.SetPathValue("dataset", strconv.FormatInt(events, 10))
	if _, ok := s.lookupRun(w, overlay); !ok {
		return
	}
	nodes := map[string]bool{}
	for _, p := range pairs {
		nodes[p.Sender] = true
		nodes[p.Receiver] = true
	}
	out := MessageFlow{Index: index, Pairs: pairs, Nodes: []string{}, From: q.Get("from_t"), To: q.Get("to_t")}
	for n := range nodes {
		out.Nodes = append(out.Nodes, n)
	}
	sort.Strings(out.Nodes)
	writeJSON(w, 200, out)
}
