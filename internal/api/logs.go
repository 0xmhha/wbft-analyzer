package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/logcat"
)

type LogInputList struct {
	Inputs []store.LogInput `json:"inputs"`
}
type LogEventPage struct {
	Events []store.LogEvent `json:"events"`
	Next   *string          `json:"next"`
}
type eventCursor struct {
	Scope string `json:"scope"`
	Wall  string `json:"wall"`
	Input string `json:"input"`
	Line  int64  `json:"line"`
}

var fullDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,155})$`)

func (s *Server) lookupRun(w http.ResponseWriter, r *http.Request) (store.Dataset, bool) {
	return s.lookupDataset(w, r, "run")
}

func (s *Server) lookupDataset(w http.ResponseWriter, r *http.Request, kind string) (store.Dataset, bool) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return store.Dataset{}, false
	}
	id, err := strconv.ParseInt(r.PathValue("dataset"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "invalid dataset ID")
		return store.Dataset{}, false
	}
	ds, err := s.Store.Datasets(r.Context(), n.ID)
	if err != nil {
		s.fail(w, r, err)
		return store.Dataset{}, false
	}
	for _, d := range ds {
		if d.ID == id {
			matches := d.Kind == kind
			if kind == "message-evidence" {
				matches = d.Kind == "messages" || d.Kind == "run"
			}
			if !matches {
				writeError(w, 400, "dataset has the wrong input kind")
				return d, false
			}
			return d, true
		}
	}
	writeError(w, 404, "dataset does not belong to this network")
	return store.Dataset{}, false
}
func (s *Server) logInputs(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	xs, err := s.Store.LogInputs(r.Context(), d.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, LogInputList{xs})
}
func (s *Server) eventBounds(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	b, err := s.Store.LogBounds(r.Context(), d.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, b)
}
func eventWindow(w http.ResponseWriter, r *http.Request) (store.EventFilter, bool) {
	q := r.URL.Query()
	for _, values := range q {
		if len(values) != 1 {
			writeError(w, 400, "duplicate event query parameter")
			return store.EventFilter{}, false
		}
	}
	f := store.EventFilter{Node: q.Get("node"), Kind: q.Get("kind"), Phase: q.Get("phase"), Height: q.Get("height"), Round: q.Get("round"), Limit: 500}
	var e1, e2 error
	f.From, e1 = time.Parse(time.RFC3339Nano, q.Get("from_t"))
	f.To, e2 = time.Parse(time.RFC3339Nano, q.Get("to_t"))
	if e1 != nil || e2 != nil || f.To.Before(f.From) || f.To.Sub(f.From) > 24*time.Hour {
		writeError(w, 400, "from_t/to_t must name an ordered window of at most 24 hours")
		return f, false
	}
	if q.Has("limit") {
		f.Limit, e1 = strconv.Atoi(q.Get("limit"))
		if e1 != nil || f.Limit < 1 || f.Limit > 1000 {
			writeError(w, 400, "limit must be 1..1000")
			return f, false
		}
	}
	if f.Node != "" && !logs.Identifier(f.Node) || f.Height != "" && !fullDecimal.MatchString(f.Height) || f.Round != "" && !fullDecimal.MatchString(f.Round) {
		writeError(w, 400, "invalid node or full decimal height/round")
		return f, false
	}
	if f.Kind != "" {
		valid := false
		for _, k := range logcat.EventKinds() {
			if f.Kind == k {
				valid = true
			}
		}
		if f.Kind == "LOG_CONFIG" || event.IsNodeKind(event.Kind(f.Kind)) {
			valid = true
		}
		if !valid {
			writeError(w, 400, "unknown event kind")
			return f, false
		}
	}
	if f.Phase != "" && f.Phase != "PRE-PREPARE" && f.Phase != "PREPARE" && f.Phase != "COMMIT" && f.Phase != "ROUND-CHANGE" {
		writeError(w, 400, "unknown message phase")
		return f, false
	}
	return f, true
}
func cursorScope(dataset int64, f store.EventFilter) string {
	b, _ := json.Marshal(struct {
		Dataset                                    int64
		From, To, Node, Kind, Phase, Height, Round string
	}{dataset, f.From.UTC().Format(time.RFC3339Nano), f.To.UTC().Format(time.RFC3339Nano), f.Node, f.Kind, f.Phase, f.Height, f.Round})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (s *Server) logEvents(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	f, ok := eventWindow(w, r)
	if !ok {
		return
	}
	scope := cursorScope(d.ID, f)
	if c := r.URL.Query().Get("cursor"); c != "" {
		raw, err := base64.RawURLEncoding.DecodeString(c)
		var cur eventCursor
		if err != nil || len(raw) > 1024 || json.Unmarshal(raw, &cur) != nil || cur.Scope != scope || !logs.Identifier(cur.Input) || cur.Line < 1 {
			writeError(w, 400, "cursor does not match this dataset and filter")
			return
		}
		t, err := time.Parse(time.RFC3339Nano, cur.Wall)
		if err != nil || t.Before(f.From.Truncate(time.Microsecond)) || t.After(f.To) {
			writeError(w, 400, "invalid cursor time")
			return
		}
		f.CursorWall = &t
		f.CursorInput = cur.Input
		f.CursorLine = cur.Line
	}
	limit := f.Limit
	f.Limit++
	rows, err := s.Store.LogEvents(r.Context(), d.ID, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	page := LogEventPage{Events: rows}
	if len(rows) > limit {
		page.Events = rows[:limit]
		last := page.Events[len(page.Events)-1]
		t, _ := time.Parse(time.RFC3339Nano, last.Wall)
		b, _ := json.Marshal(eventCursor{scope, t.Truncate(time.Microsecond).Format(time.RFC3339Nano), last.Input, last.Line})
		cursor := base64.RawURLEncoding.EncodeToString(b)
		page.Next = &cursor
	}
	writeJSON(w, 200, page)
}

func (s *Server) logRounds(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	f, ok := eventWindow(w, r)
	if !ok {
		return
	}
	out, err := s.Store.LogRounds(r.Context(), d.ID, f.From, f.To)
	if errors.Is(err, store.ErrEventWindowTooLarge) {
		writeError(w, 400, err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) logEvent(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return
	}
	input := r.PathValue("input")
	line, err := strconv.ParseInt(r.PathValue("line"), 10, 64)
	if !logs.Identifier(input) || err != nil || line < 1 {
		writeError(w, 400, "invalid input ID or line")
		return
	}
	x, err := s.Store.LogEvent(r.Context(), d.ID, input, line)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "event source is not in this run dataset")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, x)
}
