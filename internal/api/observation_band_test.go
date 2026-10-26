package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestObservationBandInspectionWithoutStore(t *testing.T) {
	raw, err := os.ReadFile("../source/observationband/testdata/normal-node-report.json")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ObservationBandInput{Report: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{}).Handler()
	call := func(data []byte, origin string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18241/v1/tools/observation-bands", bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := call(body, "")
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var out ObservationBandInspection
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.SourceScope != "node_reported" || out.Arithmetic == nil || !out.Arithmetic.MatchesReported {
		t.Fatal(out)
	}
	if w := call([]byte(`{"report":"{}"}`), ""); w.Code != http.StatusBadRequest {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call(body, "http://example.invalid"); w.Code != http.StatusForbidden {
		t.Fatal(w.Code)
	}
}
