package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func TestScenarioSourceBindingSurvivesAdoptionAndRefusesReplacement(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, original, ref := ownedDataset(t, s, "synthetic-source-binding", t.TempDir())
	source := ScenarioSource{Dataset: d.ID, ID: "registered", DeclarationSHA: strings.Repeat("a", 64), SourceSHA: strings.Repeat("b", 64), Snapshot: scenario.SourceSnapshot{Chain: ref, Events: []scenario.EventObject{{Source: scenario.Input{ID: "event", Kind: "events", Node: "node", SHA256: ref.SHA256}, Files: []messages.ArchivedFile{ref}}}}}
	if err := s.PutScenarioSource(ctx, source); err != nil {
		t.Fatal(err)
	}
	if err := s.PutScenarioSource(ctx, source); err != nil {
		t.Fatal("identical source not idempotent", err)
	}
	fence, err := s.datasetLease(ctx, d.ID, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutScenarioSource(ctx, source); !errors.Is(err, ErrDatasetBusy) {
		t.Fatal("binding crossed dataset fence", err)
	}
	fence()
	for _, change := range []func(*ScenarioSource){func(s *ScenarioSource) { s.DeclarationSHA = strings.Repeat("c", 64) }, func(s *ScenarioSource) { s.SourceSHA = strings.Repeat("c", 64) }, func(s *ScenarioSource) { s.ExecutionSHA = strings.Repeat("c", 64) }, func(s *ScenarioSource) { s.Snapshot.Chain.Path = "/private/foreign/object" }} {
		copy := source
		change(&copy)
		if err := s.PutScenarioSource(ctx, copy); !errors.Is(err, ErrScenarioState) {
			t.Fatal("source replacement accepted", err)
		}
	}
	if _, err := s.ScenarioSource(ctx, d.ID+100, "registered"); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-dataset source exposed", err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE dataset_storage SET owner=$2 WHERE dataset_id=$1`, d.ID, strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	if err := s.AdoptDatasetInputs(ctx, d.NetworkID, d.ID, filepath.Join(t.TempDir(), "adopted")); err != nil {
		t.Fatal(err)
	}
	adopted, err := s.ScenarioSource(ctx, d.ID, "registered")
	if err != nil {
		t.Fatal(err)
	}
	if adopted.SourceSHA != source.SourceSHA || adopted.DeclarationSHA != source.DeclarationSHA || adopted.Snapshot.Chain.Path == source.Snapshot.Chain.Path {
		t.Fatal("identity or object adoption lost")
	}
	for _, object := range adopted.Snapshot.Objects() {
		if _, err := os.Stat(object.Path); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutScenarioSource(ctx, adopted); err != nil {
		t.Fatal("adopted binding not reusable", err)
	}
	if _, err := s.DeleteDataset(ctx, d.NetworkID, d.ID, d.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ref.Path); err != nil {
		t.Fatal("source namespace removed", err)
	}
	if err := original.Verify(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScenarioSource(ctx, d.ID, "registered"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted source remains", err)
	}
}
