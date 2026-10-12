package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/0xmhha/wbft-analyzer/internal/derive/latency"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type PhasePage struct {
	Samples []latency.Sample `json:"samples"`
	Next    *string          `json:"next"`
	Total   int64            `json:"total"`
}
type phaseCursor struct {
	Scope  string `json:"scope"`
	Offset int    `json:"offset"`
}

func phaseMetric(metric string) bool {
	if metric == "" {
		return true
	}
	for _, m := range latency.Metrics {
		if metric == m {
			return true
		}
	}
	return false
}
func (s *Server) phaseData(w http.ResponseWriter, r *http.Request) ([]latency.Sample, store.EventFilter, bool) {
	d, ok := s.lookupRun(w, r)
	if !ok {
		return nil, store.EventFilter{}, false
	}
	f, ok := eventWindow(w, r)
	if !ok {
		return nil, f, false
	}
	metric := r.URL.Query().Get("metric")
	if !phaseMetric(metric) {
		writeError(w, 400, "unknown WBFT phase metric")
		return nil, f, false
	}
	rows, err := s.Store.PhaseSamples(r.Context(), d.ID, latency.Filter{From: f.From, To: f.To, Node: f.Node, Height: f.Height, Round: f.Round, Metric: metric})
	if errors.Is(err, store.ErrPhaseWindowTooLarge) {
		writeError(w, 400, err.Error())
		return nil, f, false
	}
	if err != nil {
		s.fail(w, r, err)
		return nil, f, false
	}
	return rows, f, true
}
func (s *Server) phaseSummary(w http.ResponseWriter, r *http.Request) {
	rows, _, ok := s.phaseData(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, latency.Summarize(rows))
}
func (s *Server) phaseSamples(w http.ResponseWriter, r *http.Request) {
	rows, f, ok := s.phaseData(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	status, clock := q.Get("status"), q.Get("clock")
	if clock != "" && clock != "wall" && clock != "monotonic" && clock != "unavailable" {
		writeError(w, 400, "unknown phase clock")
		return
	}
	validStatus := map[string]bool{"": true, "valid": true, "negative": true, "missing_start": true, "missing_end": true, "missing_both": true, "missing_clock": true, "invalid_clock": true}
	if !validStatus[status] {
		writeError(w, 400, "unknown phase sample status")
		return
	}
	var threshold *float64
	if name := q.Get("threshold"); name != "" {
		if name != "p50" && name != "p90" && name != "p95" && name != "p99" {
			writeError(w, 400, "unknown threshold percentile")
			return
		}
		if q.Get("metric") == "" || clock == "" || clock == "unavailable" {
			writeError(w, 400, "threshold needs one metric and clock")
			return
		}
		for _, g := range latency.Summarize(rows).Groups {
			if g.Node == "" && g.Metric == q.Get("metric") && g.Clock == clock {
				switch name {
				case "p50":
					threshold = g.P50
				case "p90":
					threshold = g.P90
				case "p95":
					threshold = g.P95
				case "p99":
					threshold = g.P99
				}
			}
		}
	}
	selected := []latency.Sample{}
	for _, x := range rows {
		if status != "" && x.Status != status || clock != "" && x.Clock != clock {
			continue
		}
		if q.Get("threshold") != "" && (threshold == nil || x.Status != "valid" || x.Seconds == nil || *x.Seconds < *threshold) {
			continue
		}
		selected = append(selected, x)
	}
	// Bind both filters and the derived snapshot. Appended input records
	// invalidate a cursor rather than shifting its offset underneath the reader.
	params := r.URL.Query()
	params.Del("cursor")
	params.Del("limit")
	hash := sha256.New()
	_, _ = hash.Write([]byte(r.PathValue("net") + ":" + r.PathValue("dataset") + ":" + params.Encode()))
	if err := json.NewEncoder(hash).Encode(rows); err != nil {
		s.fail(w, r, err)
		return
	}
	scope := hex.EncodeToString(hash.Sum(nil))
	offset := 0
	if value := q.Get("cursor"); value != "" {
		raw, err := base64.RawURLEncoding.DecodeString(value)
		var c phaseCursor
		if err != nil || len(raw) > 512 || json.Unmarshal(raw, &c) != nil || c.Scope != scope || c.Offset < 0 || c.Offset > len(selected) {
			writeError(w, 400, "phase cursor does not match dataset and filters")
			return
		}
		offset = c.Offset
	}
	end := offset + f.Limit
	if end > len(selected) {
		end = len(selected)
	}
	page := PhasePage{Samples: selected[offset:end], Total: int64(len(selected))}
	if end < len(selected) {
		raw, _ := json.Marshal(phaseCursor{scope, end})
		value := base64.RawURLEncoding.EncodeToString(raw)
		page.Next = &value
	}
	writeJSON(w, 200, page)
}
