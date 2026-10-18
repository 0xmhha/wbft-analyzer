package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestGovernanceStateEvidenceScopesAndAbsentProofs(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, sha, err := governance.Load("../source/governance/testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ingest.Governance(ctx, s, "state-evidence-scope", "archive", sha, a)
	if err != nil {
		t.Fatal(err)
	}
	handler := (&Server{Store: s}).Handler()
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/governance/state-witnesses/", got.NetworkID, got.DatasetID)
	for _, test := range []struct {
		path   string
		status int
	}{{base + "18446744073709551615", 200}, {base + "01", 400}, {base + "18446744073709551616", 400}, {base + "10?unexpected=true", 400}, {strings.Replace(base, fmt.Sprintf("networks/%d/", got.NetworkID), "networks/999999/", 1) + "10", 404}} {
		r := httptest.NewRequest("GET", test.path, nil)
		r.Host = "127.0.0.1:8080"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatal(test, w.Code, w.Body.String())
		}
		if w.Code == 200 {
			(client{t, handler}).conforms("GET", test.path, w)
			var evidence store.GovernanceStateEvidenceList
			if json.Unmarshal(w.Body.Bytes(), &evidence) != nil || len(evidence.Evidence) != 0 || evidence.Truncated || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing proof became a positive result", w.Body.String())
			}
		}
	}
}
