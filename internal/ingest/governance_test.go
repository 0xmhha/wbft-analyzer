package ingest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
)

func TestGovernanceImportIdempotenceAndChangedInputRefusal(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, sha, err := governance.Load("../source/governance/testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := Governance(ctx, s, "synthetic-governance", "archive", sha, a)
	if err != nil || r.Calls != 9 || r.Skipped || r.Snapshot == "" {
		t.Fatal(r, err)
	}
	again, err := Governance(ctx, s, "synthetic-governance", "archive", sha, a)
	if err != nil || !again.Skipped || again.DatasetID != r.DatasetID || again.Snapshot != r.Snapshot {
		t.Fatal(again, err)
	}
	for _, change := range []string{"source", "snapshot"} {
		kind := "archive"
		changed := a
		if change == "source" {
			kind = "rpc"
		} else {
			changed.Replies = append([]governance.Reply{}, a.Replies...)
			changed.Replies[2].Response = json.RawMessage(`{"jsonrpc":"2.0","id":3,"result":[]}`)
		}
		if _, err = Governance(ctx, s, "synthetic-governance", kind, sha, changed); err == nil {
			t.Fatal("changed input accepted", change)
		}
	}
	info, err := s.GovernanceCapture(ctx, r.DatasetID)
	if err != nil || info.Snapshot != r.Snapshot {
		t.Fatal("refusal changed completed capture", info, err)
	}
	datasets, err := s.Datasets(ctx, r.NetworkID)
	if err != nil || len(datasets) != 1 || datasets[0].Status != "complete" || datasets[0].Progress != 9 || len(datasets[0].Nodes) != 1 || len(datasets[0].CopyNodes) != 0 {
		t.Fatal(datasets, err)
	}
	if _, err = Governance(ctx, s, "bad-sha", "archive", "bad", a); err == nil {
		t.Fatal("invalid provenance accepted")
	}
}
