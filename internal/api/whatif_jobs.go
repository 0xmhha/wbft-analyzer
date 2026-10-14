package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/replayjob"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

type WhatifJobs struct {
	Jobs []store.WhatifJob `json:"jobs"`
}

func (s *Server) postWhatifJob(w http.ResponseWriter, r *http.Request) {
	dataset, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if s.Jobs == nil || !s.Jobs.Available() {
		writeError(w, 503, "experiment worker is not enabled")
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected experiment query")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	var request replayjob.WhatifRequest
	if err != nil || whatif.DecodeJSON(raw, &request) != nil {
		writeError(w, 400, "invalid experiment request")
		return
	}
	job, err := s.Jobs.SubmitWhatif(r.Context(), dataset.NetworkID, dataset.ID, request)
	switch {
	case errors.Is(err, store.ErrDatasetBusy), errors.Is(err, store.ErrDatasetDeleting):
		writeError(w, 409, "dataset is busy or being deleted")
	case errors.Is(err, store.ErrReexecQueueFull):
		writeError(w, 429, "experiment queue is full")
	case errors.Is(err, replayjob.ErrSource):
		writeError(w, 422, "registered timer experiment source unavailable")
	case errors.Is(err, replayjob.ErrScope):
		writeError(w, 400, "invalid timer policy")
	case err != nil:
		s.fail(w, r, err)
	default:
		writeJSON(w, 202, job)
	}
}
func (s *Server) whatifJobs(w http.ResponseWriter, r *http.Request) {
	dataset, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected experiment query")
		return
	}
	jobs, err := s.Store.WhatifJobs(r.Context(), dataset.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, WhatifJobs{jobs})
}
func (s *Server) whatifJob(w http.ResponseWriter, r *http.Request) {
	dataset, ok := s.lookupDataset(w, r, "messages")
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected experiment query")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("job"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "invalid experiment job ID")
		return
	}
	job, err := s.Store.WhatifJob(r.Context(), dataset.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "experiment job not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, job)
}
