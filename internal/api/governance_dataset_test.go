package api

import (
	"context"
	"fmt"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
)

func TestGovernanceDatasetFilterAndSourceNode(t *testing.T) {
	s := testStore(t)
	a, sha, err := governance.Load("../source/governance/testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ingest.Governance(context.Background(), s, "synthetic-governance", "archive", sha, a)
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	var out DatasetList
	base := fmt.Sprintf("/v1/networks/%d/datasets", r.NetworkID)
	if code := c.do("GET", base+"?kind=governance", nil, &out); code != 200 || len(out.Datasets) != 1 || out.Datasets[0].ID != r.DatasetID || out.Datasets[0].Progress != 9 || len(out.Datasets[0].Nodes) != 1 || len(out.Datasets[0].CopyNodes) != 0 {
		t.Fatal(out)
	}
	if code := c.do("GET", base+"?kind=range", nil, &out); code != 200 || len(out.Datasets) != 0 {
		t.Fatal("claim dataset treated as headers", out)
	}
	if code := c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets?kind=governance", r.NetworkID+1), nil, &out); code != 404 {
		t.Fatal("foreign dataset", out)
	}
}
