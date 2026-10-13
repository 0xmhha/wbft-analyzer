package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/replayjob"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type ReexecSources struct {
	Enabled bool                   `json:"enabled"`
	Sources []replayjob.SourceInfo `json:"sources"`
}
type ReexecJobs struct {
	Jobs []store.ReexecJob `json:"jobs"`
}

func (s *Server) reexecSources(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected replay query")
		return
	}
	out := ReexecSources{Sources: []replayjob.SourceInfo{}}
	if s.Jobs != nil {
		out.Enabled = s.Jobs.Available()
		out.Sources = s.Jobs.Sources(d.NetworkID, d.ID)
	}
	writeJSON(w, 200, out)
}
func (s *Server) postReexecJob(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if s.Jobs == nil || !s.Jobs.Available() {
		writeError(w, 503, "replay worker is not enabled")
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected replay query")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	var request replayjob.Request
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, 400, "invalid replay job request")
		return
	}
	if request.Mode == "" {
		request.Mode = "closed"
	}
	job, err := s.Jobs.Submit(r.Context(), d.NetworkID, d.ID, request)
	switch {
	case errors.Is(err, store.ErrDatasetBusy), errors.Is(err, store.ErrDatasetDeleting):
		writeError(w, 409, "dataset is busy or being deleted")
	case errors.Is(err, store.ErrReexecQueueFull):
		writeError(w, 429, "replay queue is full")
	case errors.Is(err, replayjob.ErrSource):
		writeError(w, 422, "retained replay source unavailable")
	case errors.Is(err, replayjob.ErrScope):
		writeError(w, 400, "invalid replay scope or mode")
	case err != nil:
		s.fail(w, r, err)
	default:
		writeJSON(w, 202, job)
	}
}
func (s *Server) reexecJobs(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected replay query")
		return
	}
	jobs, err := s.Store.ReexecJobs(r.Context(), d.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, ReexecJobs{jobs})
}
func (s *Server) reexecJob(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected replay query")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("job"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "invalid replay job ID")
		return
	}
	job, err := s.Store.ReexecJob(r.Context(), d.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "replay job not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, job)
}
