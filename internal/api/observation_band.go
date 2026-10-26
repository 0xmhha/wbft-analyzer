package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/0xmhha/wbft-analyzer/internal/source/observationband"
)

type ObservationBandInput struct {
	Report string `json:"report"`
}
type ObservationBandInspection observationband.Inspection

// inspectObservationBand performs no database write, node query or replay.
func (s *Server) inspectObservationBand(w http.ResponseWriter, r *http.Request) {
	limit := min(s.maxBody(), 128<<10)
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		writeError(w, http.StatusRequestEntityTooLarge, "observation report exceeds the inspection limit")
		return
	}
	var input ObservationBandInput
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid observation report request")
		return
	}
	result, err := observationband.Inspect([]byte(input.Report))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ObservationBandInspection(*result))
}
