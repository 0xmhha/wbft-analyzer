package scenariojob

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft/types"
)

func TestPublicEpochEvidencePreservesOrderAndLargeHeight(t *testing.T) {
	a, b := types.Address{19: 1}, types.Address{19: 2}
	e := publicEpochs([]scenario.RecordedEpoch{{Block: ^uint64(0), Candidates: []types.Address{a, b}, Validators: []types.Address{b, a}, HeaderInputsVerified: true}})
	if len(e) != 1 || e[0].Block != "18446744073709551615" || e[0].Candidates[0] != a.Hex() || e[0].Validators[0] != b.Hex() || !e[0].HeaderInputsVerified {
		t.Fatal(e)
	}
	if publicEpochs(nil) == nil {
		t.Fatal("absent epoch history must be an empty array")
	}
}

func TestScenarioRegistryRejectsUnsafeOrAmbiguousConfiguration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sources.json")
	for _, raw := range []string{`[]`, `[] {}`, `[{"id":"one","id":"two"}]`, `[{"id":"one","unknown":true}]`, string(make([]byte, (256<<10)+1))} {
		if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(context.Background(), nil, p); !errors.Is(err, ErrSource) {
			t.Fatal("invalid configuration accepted", err)
		}
	}
	if err := os.WriteFile(p, []byte(`[]`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), nil, p); !errors.Is(err, ErrSource) {
		t.Fatal("public configuration accepted", err)
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), nil, link); !errors.Is(err, ErrSource) {
		t.Fatal("symlink configuration accepted", err)
	}
}

func TestScenarioRegistryKeepsPartialModelsReadOnlyAndScoped(t *testing.T) {
	w := &Worker{sources: map[string]registered{"partial": {network: 1, info: SourceInfo{ID: "partial", Dataset: 2, Status: "partial", SourceSHA: "synthetic", Model: scenario.Assessment{Version: scenario.FitVersion, Status: "partial"}}}}, order: []string{"partial"}}
	if len(w.Sources(1, 2)) != 1 || len(w.Sources(9, 2)) != 0 || len(w.Sources(1, 9)) != 0 {
		t.Fatal("registry scope ignored")
	}
	for _, s := range []struct {
		network, dataset int64
		id               string
	}{{1, 2, "partial"}, {9, 2, "partial"}, {1, 9, "partial"}, {1, 2, "/private/path"}} {
		if _, err := w.Enqueue(context.Background(), s.network, s.dataset, s.id, scenario.CutOutgoing{Kind: "cut_outgoing", Node: 0, ToNS: 1}); !errors.Is(err, ErrSource) {
			t.Fatal("unproved or unregistered model reached storage", err)
		}
	}
}

func TestEmptyScenarioRegistryDoesNotClaimQueue(t *testing.T) {
	w := NewEmpty(nil)
	if claimed, err := w.ExecuteNext(context.Background(), "unconfigured"); err != nil || claimed {
		t.Fatal("unconfigured worker reached the execution queue", claimed, err)
	}
	if got := w.Sources(1, 1); got == nil || len(got) != 0 {
		t.Fatal("empty sources must remain readable", got)
	}
}

func TestScenarioRegistryRejectsChangeOutsideFittedScope(t *testing.T) {
	w := &Worker{sources: map[string]registered{"complete": {network: 1, nodes: 4, duration: time.Second, info: SourceInfo{ID: "complete", Dataset: 2, Status: "complete", ExecutionSHA: "synthetic"}}}}
	for _, change := range []scenario.CutOutgoing{{Kind: "cut_outgoing", Node: 4, ToNS: 1}, {Kind: "cut_outgoing", Node: 0, ToNS: int64(2 * time.Second)}, {Kind: "unknown", Node: 0, ToNS: 1}} {
		if _, err := w.Enqueue(context.Background(), 1, 2, "complete", change); !errors.Is(err, ErrChange) {
			t.Fatal("change exceeded registered model", err)
		}
	}
}
