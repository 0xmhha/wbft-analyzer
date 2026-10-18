package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type EpochRegistryPage struct {
	Index    string                   `json:"index"`
	Hash     string                   `json:"hash"`
	Status   string                   `json:"status" enum:"available,genesis,not_epoch"`
	Snapshot string                   `json:"snapshot"`
	Rows     []store.EpochRegistryRow `json:"rows"`
	Total    int64                    `json:"total"`
	Next     *string                  `json:"next"`
}

type epochRegistryCursor struct {
	Scope  string `json:"scope"`
	Offset int64  `json:"offset"`
}

func (s *Server) epochRegistryEffects(w http.ResponseWriter, r *http.Request) {
	network, ok := s.lookupNetwork(w, r)
	if !ok {
		return
	}
	index := r.PathValue("index")
	q := r.URL.Query()
	for key, values := range q {
		if (key != "limit" && key != "cursor") || len(values) != 1 {
			writeError(w, 400, "invalid epoch registry page filter")
			return
		}
	}
	limit := 10
	if q.Has("limit") {
		value, err := strconv.Atoi(q.Get("limit"))
		if err != nil || value < 1 || value > 20 || strconv.Itoa(value) != q.Get("limit") {
			writeError(w, 400, "limit must be 1..20")
			return
		}
		limit = value
	}
	cursor := epochRegistryCursor{}
	if q.Has("cursor") {
		encoded := q.Get("cursor")
		if len(encoded) > 700 {
			writeError(w, 400, "invalid epoch registry cursor")
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || jsonmeta.Decode(raw, 512, true, &cursor) != nil || len(cursor.Scope) != 64 || cursor.Offset < 0 {
			writeError(w, 400, "invalid epoch registry cursor")
			return
		}
		if _, err := hex.DecodeString(cursor.Scope); err != nil {
			writeError(w, 400, "invalid epoch registry cursor")
			return
		}
	}
	result, err := s.Store.EpochRegistryEffects(r.Context(), network.ID, index, cursor.Offset, limit, cursor.Scope)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "canonical header not found")
		return
	case errors.Is(err, store.ErrGovernanceQuery):
		writeError(w, 400, "invalid canonical index or epoch registry page scope")
		return
	case errors.Is(err, store.ErrEpochRegistrySnapshot):
		writeError(w, 409, "epoch registry source set changed; refresh from the first page")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	page := EpochRegistryPage{Index: result.Index, Hash: result.Hash, Status: result.Status, Snapshot: result.Snapshot, Rows: result.Rows, Total: result.Total}
	if result.Next != nil {
		raw, _ := json.Marshal(epochRegistryCursor{Scope: result.Snapshot, Offset: *result.Next})
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.Next = &next
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, page)
}

func epochRegistryParams() []param {
	return []param{netPath,
		{name: "index", in: "path", doc: "canonical decimal uint64 epoch block index", typ: "string", required: true},
		{name: "limit", in: "query", doc: "page size 1..20; state and effect rows share the same stable page order", typ: "integer"},
		{name: "cursor", in: "query", doc: "canonical header and immutable source-set-bound cursor; live original-source binding is rechecked on every read", typ: "string"},
	}
}
