package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	derived "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"net/http"
	"strconv"
	"time"
)

type PairSummary struct {
	Index   store.PairIndex        `json:"index"`
	Summary derived.PairStatistics `json:"summary"`
}
type PairPage struct {
	Index     store.PairIndex `json:"index"`
	Pairs     []derived.Pair  `json:"pairs"`
	Total     int64           `json:"total"`
	Threshold *float64        `json:"threshold_seconds"`
	Next      *string         `json:"next"`
}

type PairTimeSeries struct {
	Index  store.PairIndex    `json:"index"`
	Series derived.TimeSeries `json:"series"`
}

func (s *Server) pairSeries(w http.ResponseWriter, r *http.Request) {
	index, pairs, _, ok := s.pairData(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	if q.Has("cursor") || q.Has("limit") || q.Has("threshold") {
		writeError(w, 400, "series does not accept sample paging or threshold")
		return
	}
	series := derived.Series(pairs, 1)
	if len(series.Points) > 2000 {
		writeError(w, 400, "message series exceeds 2000 buckets/views; narrow the filters")
		return
	}
	writeJSON(w, 200, PairTimeSeries{index, series})
}

func oneOf(x string, values ...string) bool {
	if x == "" {
		return true
	}
	for _, v := range values {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) pairData(w http.ResponseWriter, r *http.Request, flow ...bool) (store.PairIndex, []derived.Pair, int, bool) {
	d, ok := s.lookupDataset(w, r, "message-evidence")
	if !ok {
		return store.PairIndex{}, nil, 0, false
	}
	q := r.URL.Query()
	allowed := map[string]bool{"from_t": true, "to_t": true, "sender": true, "receiver": true, "node": true, "phase": true, "height": true, "round": true, "strength": true, "path": true, "clock": true, "status": true, "limit": true, "cursor": true, "threshold": true, "metric": true, "events": len(flow) > 0}
	bad := func(message string) (store.PairIndex, []derived.Pair, int, bool) {
		writeError(w, 400, message)
		return store.PairIndex{}, nil, 0, false
	}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			return bad("invalid message pair query")
		}
	}
	f := store.PairFilter{Sender: q.Get("sender"), Receiver: q.Get("receiver"), Node: q.Get("node"), Phase: q.Get("phase"), Height: q.Get("height"), Round: q.Get("round"), Strength: q.Get("strength"), Path: q.Get("path"), Clock: q.Get("clock"), Status: q.Get("status"), Metric: q.Get("metric")}
	for _, n := range []string{f.Sender, f.Receiver, f.Node} {
		if n != "" && !logs.Identifier(n) {
			return bad("invalid message node")
		}
	}
	if f.Height != "" && !fullDecimal.MatchString(f.Height) || f.Round != "" && !fullDecimal.MatchString(f.Round) {
		return bad("invalid full message view")
	}
	if !oneOf(f.Metric, "link", "propagation_processing", "broadcast_to_receipt") {
		return bad("unknown message boundary metric")
	}
	if !oneOf(f.Phase, "PRE-PREPARE", "PREPARE", "COMMIT", "ROUND-CHANGE") || !oneOf(f.Strength, "link", "node", "key") || !oneOf(f.Path, "local", "direct", "relay", "propagation_processing") || !oneOf(f.Clock, "shared-host", "ntp", "monotonic", "unknown", "unavailable") || !oneOf(f.Status, "valid", "ambiguous", "missing_send", "missing_receive", "unconfirmed_write", "unknown_clock", "clock_overlap", "negative", "missing_clock", "invalid_clock") {
		return bad("unknown message pair filter")
	}
	if q.Has("from_t") || q.Has("to_t") {
		var a, b error
		f.From, a = time.Parse(time.RFC3339Nano, q.Get("from_t"))
		f.To, b = time.Parse(time.RFC3339Nano, q.Get("to_t"))
		if a != nil || b != nil || f.To.Before(f.From) || f.To.Sub(f.From) > 24*time.Hour {
			return bad("from_t/to_t must name an ordered window of at most 24 hours")
		}
	}
	limit := 500
	if q.Has("limit") {
		n, e := strconv.Atoi(q.Get("limit"))
		if e != nil || n < 1 || n > 1000 {
			return bad("limit must be 1..1000")
		}
		limit = n
	}
	if len(flow) > 0 {
		f.Overlap = true
		f.MaxPairs = 2000
	}
	index, pairs, e := s.Store.MessagePairData(r.Context(), d.ID, f)
	if errors.Is(e, store.ErrPairIndex) {
		writeError(w, 409, e.Error())
		return index, nil, 0, false
	}
	if errors.Is(e, store.ErrPairWindow) {
		if len(flow) > 0 {
			return bad("message flow exceeds 2000 groups; narrow the filters")
		}
		return bad(e.Error())
	}
	if e != nil {
		s.fail(w, r, e)
		return index, nil, 0, false
	}
	return index, pairs, limit, true
}
func (s *Server) pairSummary(w http.ResponseWriter, r *http.Request) {
	index, pairs, _, ok := s.pairData(w, r)
	if !ok {
		return
	}
	if r.URL.Query().Has("threshold") || r.URL.Query().Has("cursor") || r.URL.Query().Has("limit") {
		writeError(w, 400, "summary does not accept paging or threshold")
		return
	}
	writeJSON(w, 200, PairSummary{index, derived.Summarize(pairs)})
}
func (s *Server) pairSamples(w http.ResponseWriter, r *http.Request) {
	index, pairs, limit, ok := s.pairData(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	var threshold *float64
	if name := q.Get("threshold"); name != "" {
		if !oneOf(name, "p50", "p90", "p95", "p99") || q.Get("phase") == "" || q.Get("strength") == "" || q.Get("path") == "" || q.Get("clock") == "" {
			writeError(w, 400, "threshold needs one phase, strength, path and clock")
			return
		}
		overallGroups := 0
		for _, g := range derived.Summarize(pairs).Groups {
			if g.Key.Scope != "overall" {
				continue
			}
			overallGroups++
			switch name {
			case "p50":
				threshold = g.Distribution.P50
			case "p90":
				threshold = g.Distribution.P90
			case "p95":
				threshold = g.Distribution.P95
			case "p99":
				threshold = g.Distribution.P99
			}
		}
		if overallGroups > 1 {
			writeError(w, 400, "threshold needs one boundary metric")
			return
		}
	}
	selected := []derived.Pair{}
	for _, p := range pairs {
		if q.Get("threshold") != "" && (threshold == nil || p.Status != "valid" || p.Seconds == nil || *p.Seconds < *threshold) {
			continue
		}
		selected = append(selected, p)
	}
	params := r.URL.Query()
	params.Del("cursor")
	params.Del("limit")
	hash := sha256.New()
	_, _ = hash.Write([]byte(r.PathValue("net") + ":" + r.PathValue("dataset") + ":" + params.Encode()))
	if e := json.NewEncoder(hash).Encode(struct {
		Index store.PairIndex
		Pairs []derived.Pair
	}{index, pairs}); e != nil {
		s.fail(w, r, e)
		return
	}
	scope := hex.EncodeToString(hash.Sum(nil))
	offset := 0
	if v := q.Get("cursor"); v != "" {
		raw, e := base64.RawURLEncoding.DecodeString(v)
		var c phaseCursor
		if e != nil || len(raw) > 512 || json.Unmarshal(raw, &c) != nil || c.Scope != scope || c.Offset < 0 || c.Offset > len(selected) {
			writeError(w, 400, "pair cursor does not match dataset and filters")
			return
		}
		offset = c.Offset
	}
	end := min(offset+limit, len(selected))
	page := PairPage{Index: index, Pairs: selected[offset:end], Total: int64(len(selected)), Threshold: threshold}
	if end < len(selected) {
		raw, _ := json.Marshal(phaseCursor{scope, end})
		v := base64.RawURLEncoding.EncodeToString(raw)
		page.Next = &v
	}
	writeJSON(w, 200, page)
}
