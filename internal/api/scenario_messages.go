package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/scenariojob"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type ScenarioMessagePage struct {
	SourceSHA256 string                             `json:"source_sha256"`
	Verification string                             `json:"verification"`
	Messages     []scenario.RecordedMessageEvidence `json:"messages"`
	Next         *string                            `json:"next"`
}
type scenarioMessageCursor struct {
	Scope   string `json:"scope"`
	File    string `json:"file"`
	Ordinal int64  `json:"ordinal,string"`
}

func (s *Server) scenarioMessages(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if s.Scenarios == nil {
		writeError(w, 422, "registered scenario model unavailable")
		return
	}
	q := r.URL.Query()
	for key, values := range q {
		if len(values) != 1 || key != "source" && key != "input" && key != "height" && key != "round" && key != "cursor" {
			writeError(w, 400, "invalid recorded message selection query")
			return
		}
	}
	if !logs.Identifier(q.Get("source")) || !logs.Identifier(q.Get("input")) {
		writeError(w, 400, "source and input are required")
		return
	}
	for _, key := range []string{"height", "round"} {
		if q.Has(key) && (len(q.Get(key)) > 156 || !fullDecimal.MatchString(q.Get(key))) {
			writeError(w, 400, "invalid message view filter")
			return
		}
	}
	sourceSHA := ""
	for _, source := range s.Scenarios.Sources(d.NetworkID, d.ID) {
		if source.ID == q.Get("source") {
			sourceSHA = source.SourceSHA
		}
	}
	if sourceSHA == "" {
		writeError(w, 422, "registered scenario model unavailable")
		return
	}
	raw, _ := json.Marshal([]any{d.NetworkID, d.ID, q.Get("source"), sourceSHA, q.Get("input"), q.Get("height"), q.Get("round")})
	hash := sha256.Sum256(raw)
	scope := hex.EncodeToString(hash[:])
	filter := store.MessageFilter{Input: q.Get("input"), Height: q.Get("height"), Round: q.Get("round")}
	if q.Has("cursor") {
		raw, err := base64.RawURLEncoding.DecodeString(q.Get("cursor"))
		var cursor scenarioMessageCursor
		if err != nil || len(raw) > 1024 || json.Unmarshal(raw, &cursor) != nil || cursor.Scope != scope || cursor.Ordinal < 1 || cursor.File == "" || len(cursor.File) > 160 || strings.ContainsAny(cursor.File, "/\\") {
			writeError(w, 400, "message cursor does not match registered source and filters")
			return
		}
		filter.AfterInput, filter.AfterFile, filter.AfterOrdinal = filter.Input, cursor.File, cursor.Ordinal
	}
	rows, next, actualSHA, err := s.Scenarios.MessageCandidates(r.Context(), d.NetworkID, d.ID, q.Get("source"), filter)
	if errors.Is(err, scenariojob.ErrChange) {
		writeError(w, 400, "input is outside registered transport scope")
		return
	}
	if errors.Is(err, scenariojob.ErrSource) {
		writeError(w, 422, "registered scenario model unavailable")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if actualSHA != sourceSHA {
		writeError(w, 409, "registered source changed")
		return
	}
	page := ScenarioMessagePage{SourceSHA256: sourceSHA, Verification: "metadata_projection_only_full_frame_and_signature_validation_on_queue", Messages: rows}
	if next != nil {
		raw, _ := json.Marshal(scenarioMessageCursor{Scope: scope, File: next.File, Ordinal: next.Ordinal})
		cursor := base64.RawURLEncoding.EncodeToString(raw)
		page.Next = &cursor
	}
	writeJSON(w, 200, page)
}
