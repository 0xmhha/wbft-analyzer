package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type RuntimeSummary struct {
	Startup                            *runtimeobs.Point `json:"startup"`
	Normalizer                         string            `json:"normalizer"`
	SourceSHA                          string            `json:"source_sha256"`
	Node                               string            `json:"node"`
	Run                                string            `json:"run"`
	Complete                           bool              `json:"capture_complete"`
	SequenceGaps                       string            `json:"sequence_gaps"`
	Unavailable                        []string          `json:"unavailable"`
	CallCount                          int               `json:"call_count"`
	PointCount                         int               `json:"point_count"`
	RuntimeModelComplete               bool              `json:"runtime_model_complete"`
	DeliveryCoverageProven             bool              `json:"delivery_coverage_proven"`
	ApplicationRequestCompletionProven bool              `json:"application_request_completion_proven"`
}
type RuntimeCallPage struct {
	Calls []runtimeobs.Call `json:"calls"`
	Next  *int              `json:"next"`
}
type RuntimeCallSource struct {
	Call      runtimeobs.Call  `json:"call"`
	Start     runtimeobs.Point `json:"start"`
	End       runtimeobs.Point `json:"end"`
	SourceSHA string           `json:"source_sha256"`
	Node      string           `json:"node"`
	Run       string           `json:"run"`
}

func (s *Server) runtimeData(w http.ResponseWriter, r *http.Request) (runtimeobs.Capture, bool) {
	d, ok := s.lookupDataset(w, r, "runtime")
	if !ok {
		return runtimeobs.Capture{}, false
	}
	c, e := s.Store.RuntimeCapture(r.Context(), d.ID)
	if errors.Is(e, store.ErrNotFound) {
		writeError(w, 409, "runtime capture is not ready")
		return c, false
	}
	if e != nil {
		s.fail(w, r, e)
		return c, false
	}
	return c, true
}
func (s *Server) runtimeSummary(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "runtime summary does not accept filters")
		return
	}
	c, ok := s.runtimeData(w, r)
	if !ok {
		return
	}
	var startup *runtimeobs.Point
	for _, p := range c.Points {
		if p.Type == "runtime_start" {
			copy := p
			startup = &copy
			break
		}
	}
	writeJSON(w, 200, RuntimeSummary{startup, c.Normalizer, c.SourceSHA, c.Node, c.Run, c.Complete, c.SequenceGaps, c.Unavailable, len(c.Calls), len(c.Points), false, false, false})
}
func (s *Server) runtimeCalls(w http.ResponseWriter, r *http.Request) {
	for k := range r.URL.Query() {
		if k != "after" {
			writeError(w, 400, "unknown runtime filter")
			return
		}
	}
	after := 0
	if raw := r.URL.Query().Get("after"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 0 {
			writeError(w, 400, "invalid runtime cursor")
			return
		}
		after = n
	}
	c, ok := s.runtimeData(w, r)
	if !ok {
		return
	}
	if after > len(c.Calls) {
		writeError(w, 400, "runtime cursor outside capture")
		return
	}
	end := min(after+100, len(c.Calls))
	out := RuntimeCallPage{Calls: c.Calls[after:end]}
	if end < len(c.Calls) {
		out.Next = &end
	}
	writeJSON(w, 200, out)
}
func (s *Server) runtimeCall(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("call")
	n, e := strconv.ParseUint(id, 10, 64)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != id || len(r.URL.Query()) != 0 {
		writeError(w, 400, "invalid runtime call identity")
		return
	}
	c, ok := s.runtimeData(w, r)
	if !ok {
		return
	}
	for _, x := range c.Calls {
		if x.ID != id {
			continue
		}
		if x.StartLine < 1 || x.EndLine < 1 || x.StartLine > len(c.Points) || x.EndLine > len(c.Points) {
			s.fail(w, r, errors.New("runtime source invalid"))
			return
		}
		writeJSON(w, 200, RuntimeCallSource{x, c.Points[x.StartLine-1], c.Points[x.EndLine-1], c.SourceSHA, c.Node, c.Run})
		return
	}
	writeError(w, 404, "runtime call not found")
}
