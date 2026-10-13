package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"net/http"
	"strconv"
)

type MessageIssuePage struct {
	Index  store.PairIndex      `json:"index"`
	Issues []store.MessageIssue `json:"issues"`
	Total  int64                `json:"total"`
	Next   *string              `json:"next"`
}

func (s *Server) messageIssues(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "message-evidence")
	if !ok {
		return
	}
	q := r.URL.Query()
	allowed := map[string]bool{"node": true, "reason": true, "source_dataset": true, "limit": true, "cursor": true}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			writeError(w, 400, "invalid message issue query")
			return
		}
	}
	f := store.IssueFilter{Node: q.Get("node"), Reason: q.Get("reason")}
	if f.Node != "" && !logs.Identifier(f.Node) || f.Reason != "" && !logs.Identifier(f.Reason) {
		writeError(w, 400, "invalid issue source filter")
		return
	}
	if q.Has("source_dataset") {
		id, e := strconv.ParseInt(q.Get("source_dataset"), 10, 64)
		if e != nil || id <= 0 {
			writeError(w, 400, "source_dataset must be positive")
			return
		}
		f.SourceDataset = id
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
			writeError(w, 400, "invalid issue cursor")
			return
		}
	}
	index, rows, total, e := s.Store.MessageIssueData(r.Context(), d.ID, f, int64(c.Offset), limit)
	if errors.Is(e, store.ErrPairIndex) {
		writeError(w, 409, e.Error())
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
		writeError(w, 400, "issue cursor does not match snapshot and source filters")
		return
	}
	page := MessageIssuePage{Index: index, Issues: rows, Total: total}
	if len(rows) > limit {
		page.Issues = rows[:limit]
		raw, _ := json.Marshal(phaseCursor{scope, int(page.Issues[len(page.Issues)-1].Ordinal)})
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.Next = &next
	}
	writeJSON(w, 200, page)
}
