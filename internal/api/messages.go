package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type MessageInputList struct {
	Inputs []store.MessageInput `json:"inputs"`
}
type MessagePage struct {
	Records []messages.Record `json:"records"`
	Next    *string           `json:"next"`
}
type messageCursor struct {
	Scope   string `json:"scope"`
	Input   string `json:"input"`
	File    string `json:"file"`
	Ordinal int64  `json:"ordinal"`
}

func (s *Server) messageInputs(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	xs, e := s.Store.MessageInputs(r.Context(), d.ID)
	if e != nil {
		s.fail(w, r, e)
		return
	}
	writeJSON(w, 200, MessageInputList{xs})
}

func (s *Server) messageSource(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	q := r.URL.Query()
	for k, v := range q {
		if (k != "input" && k != "file" && k != "ordinal") || len(v) != 1 {
			writeError(w, 400, "invalid message source query")
			return
		}
	}
	ordinal, e := strconv.ParseInt(q.Get("ordinal"), 10, 64)
	if e != nil || ordinal < 1 || !logs.Identifier(q.Get("input")) || q.Get("file") == "" || len(q.Get("file")) > 160 || strings.ContainsAny(q.Get("file"), "/\\") {
		writeError(w, 400, "invalid original message source pointer")
		return
	}
	x, e := s.Store.MessageRecordAt(r.Context(), d.ID, q.Get("input"), q.Get("file"), ordinal)
	if errors.Is(e, store.ErrNotFound) {
		writeError(w, 404, "message source not found")
		return
	}
	if e != nil {
		s.fail(w, r, e)
		return
	}
	writeJSON(w, 200, x)
}
func (s *Server) messageRecords(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	q := r.URL.Query()
	allowed := map[string]bool{"input": true, "type": true, "node": true, "height": true, "round": true, "phase": true, "limit": true, "cursor": true}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			writeError(w, 400, "invalid message query")
			return
		}
	}
	f := store.MessageFilter{Input: q.Get("input"), Type: q.Get("type"), Node: q.Get("node"), Height: q.Get("height"), Round: q.Get("round"), Phase: q.Get("phase"), Limit: 500}
	if f.Input != "" && !logs.Identifier(f.Input) || f.Node != "" && !logs.Identifier(f.Node) || f.Height != "" && !fullDecimal.MatchString(f.Height) || f.Round != "" && !fullDecimal.MatchString(f.Round) {
		writeError(w, 400, "invalid message filter")
		return
	}
	if f.Phase != "" && f.Phase != "PRE-PREPARE" && f.Phase != "PREPARE" && f.Phase != "COMMIT" && f.Phase != "ROUND-CHANGE" {
		writeError(w, 400, "unknown message phase")
		return
	}
	if f.Type != "" && !strings.Contains("|segment|conn|frame|outcome|send_suppressed|step|gap|timer_operation|own_input|scheduler_trace|scheduler_step|cache_trace|cache_instance|cache_operation|", "|"+f.Type+"|") {
		writeError(w, 400, "unknown message type")
		return
	}
	if q.Has("limit") {
		n, e := strconv.Atoi(q.Get("limit"))
		if e != nil || n < 1 || n > 1000 {
			writeError(w, 400, "limit must be 1..1000")
			return
		}
		f.Limit = n
	}
	b, _ := json.Marshal(struct {
		Dataset  int64
		Filter   store.MessageFilter
		Metadata json.RawMessage
		Status   string
		Progress int64
	}{d.ID, store.MessageFilter{Input: f.Input, Type: f.Type, Node: f.Node, Height: f.Height, Round: f.Round, Phase: f.Phase}, d.Metadata, d.Status, d.Progress})
	sum := sha256.Sum256(b)
	scope := hex.EncodeToString(sum[:])
	if c := q.Get("cursor"); c != "" {
		b, e := base64.RawURLEncoding.DecodeString(c)
		var cur messageCursor
		if e != nil || len(b) > 1024 || json.Unmarshal(b, &cur) != nil || cur.Scope != scope || !logs.Identifier(cur.Input) || len(cur.File) > 160 || strings.ContainsAny(cur.File, "/\\") || cur.Ordinal < 1 {
			writeError(w, 400, "message cursor does not match snapshot and filters")
			return
		}
		f.AfterInput = cur.Input
		f.AfterFile = cur.File
		f.AfterOrdinal = cur.Ordinal
	}
	limit := f.Limit
	f.Limit++
	xs, e := s.Store.MessageRecords(r.Context(), d.ID, f)
	if e != nil {
		s.fail(w, r, e)
		return
	}
	out := MessagePage{Records: xs}
	if len(xs) > limit {
		out.Records = xs[:limit]
		last := out.Records[limit-1]
		b, _ := json.Marshal(messageCursor{scope, last.Input, last.File, last.Ordinal})
		next := base64.RawURLEncoding.EncodeToString(b)
		out.Next = &next
	}
	writeJSON(w, 200, out)
}
