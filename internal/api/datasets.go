package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/inputs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type DeleteDatasetRequest struct {
	ConfirmName string `json:"confirm_name"`
}

func (s *Server) datasetScope(w http.ResponseWriter, r *http.Request) (int64, int64, bool) {
	n, ok := s.lookupNetwork(w, r)
	if !ok {
		return 0, 0, false
	}
	id, e := strconv.ParseInt(r.PathValue("dataset"), 10, 64)
	if e != nil || id < 1 {
		writeError(w, 400, "invalid dataset ID")
		return 0, 0, false
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "unexpected dataset query")
		return 0, 0, false
	}
	return n.ID, id, true
}
func (s *Server) datasetStorage(w http.ResponseWriter, r *http.Request) {
	network, id, ok := s.datasetScope(w, r)
	if !ok {
		return
	}
	out, e := s.Store.DatasetInputStorage(r.Context(), network, id)
	if errors.Is(e, store.ErrNotFound) {
		writeError(w, 404, "dataset not found")
		return
	}
	if e != nil {
		s.fail(w, r, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) datasetDeletion(w http.ResponseWriter, r *http.Request) {
	network, id, ok := s.datasetScope(w, r)
	if !ok {
		return
	}
	out, e := s.Store.DatasetDeletion(r.Context(), network, id)
	if errors.Is(e, store.ErrNotFound) {
		writeError(w, 404, "dataset deletion not found")
		return
	}
	if e != nil {
		s.fail(w, r, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) deleteDataset(w http.ResponseWriter, r *http.Request) {
	network, id, ok := s.datasetScope(w, r)
	if !ok {
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	var request DeleteDatasetRequest
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || len(request.ConfirmName) == 0 || len(request.ConfirmName) > 256 {
		writeError(w, 400, "confirm the exact dataset name")
		return
	}
	out, e := s.Store.DeleteDataset(r.Context(), network, id, request.ConfirmName)
	switch {
	case errors.Is(e, store.ErrNotFound):
		writeError(w, 404, "dataset not found")
	case errors.Is(e, store.ErrDatasetConfirm):
		writeError(w, 409, "dataset name confirmation does not match")
	case errors.Is(e, store.ErrDatasetBusy):
		writeError(w, 409, "dataset has an active import, replay or input adoption")
	case errors.Is(e, store.ErrDatasetReferenced):
		writeError(w, 409, "dataset is referenced by a follow capture")
	case errors.Is(e, store.ErrUnmanagedInputs), errors.Is(e, inputs.ErrOwnership):
		writeError(w, 409, "input ownership is unavailable; adopt inputs or repair owned storage before retrying")
	case e != nil:
		s.fail(w, r, e)
	default:
		writeJSON(w, 200, out)
	}
}
