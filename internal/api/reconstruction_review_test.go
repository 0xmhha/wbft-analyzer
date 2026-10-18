package api

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/reconstruct"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestReconstructionReviewScopesAndOriginalCoordinates(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	raw, err := os.ReadFile("../reconstruct/testdata/review.json")
	if err != nil {
		t.Fatal(err)
	}
	var p reconstruct.ReviewPacket
	if err = json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: p.Network.ChainID, GenesisHash: p.Network.Genesis}, "synthetic-step-review", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	input := logs.InputSummary{ID: "log", Node: p.Node, Profile: p.Source.LogProfile, ProfileSHA256: p.Source.LogProfileSHA, SHA256: p.Source.LogSHA, Bytes: 100}
	if err = s.PutLogInput(ctx, d.ID, input); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, d.ID, 100, ""); err != nil {
		t.Fatal(err)
	}
	release()
	source := p.Source
	result := reconstruct.ExecutionResult{ExecutionVersion: p.ExecutionVersion, CoreVersion: p.CoreVersion, ComparisonModel: p.ComparisonModel, AllImprovementsOff: true,
		Assessment: reconstruct.Assessment{Version: reconstruct.Version, Phase: "reconstructed_execution", Node: p.Node, ChainID: p.Network.ChainID, GenesisHash: p.Network.Genesis, From: p.Height.Height, To: p.Height.Height, CoreExecuted: true,
			Heights: []reconstruct.Height{{Height: p.Height.Height, Status: p.Height.Status, Issues: p.Height.Issues, Evidence: []reconstruct.Evidence{}}},
			Sources: reconstruct.Sources{LogBytes: 100, LogSHA: source.LogSHA, LogProfile: source.LogProfile, LogProfileSHA: source.LogProfileSHA, LogNormalizer: source.LogNormalizer, GenesisSHA: source.GenesisSHA, ChainSHA: source.ChainSHA, ProcessingScopes: []reconstruct.ProcessingScope{}, Frames: &messages.Summary{ID: "frames", Kind: "frames", Node: p.Node, SHA256: source.FrameSHA, Files: []messages.File{}}, Inputs: &reconstruct.InputObservationSummary{Format: source.ProcessingFormat, Normalizer: source.ProcessingNormalizer, SHA256: source.ProcessingSHA, Run: source.ProcessingRun, FrameRun: source.FrameRun, SourceCommit: source.SourceCommit, BinarySHA: source.BinarySHA, GenesisSHA: source.GenesisSHA, CaptureComplete: source.CaptureComplete, Unavailable: source.CaptureIssues}}},
		Executions: []reconstruct.HeightExecution{{Height: p.Height.Height, Run: p.LogRun, Status: p.Height.Status, Issues: p.Height.Issues, Steps: []reconstruct.ExecutionStep{p.Step}, Differences: int64(len(p.Step.Differences))}}}
	id, err := s.PutReconstruction(ctx, d.ID, "log", result)
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/reconstruction/%d/steps", d.NetworkID, d.ID, id)
	var got reconstruct.ReviewPacket
	if c.do("GET", base+"/1/review", nil, &got) != 200 || got.Position != 1 || got.Step.Input.Ordinal != "4" || got.Step.Input.Source.Sequence != "9007199254740993" || got.Step.Input.ObservationInstance != "2" || got.Height.Status != "partial" || got.SpecificationVerdict != "not_evaluated" {
		t.Fatal(got)
	}
	for suffix, want := range map[string]int{"/0/review": 400, "/2/review": 404, "/1/review?raw=true": 400} {
		if c.do("GET", base+suffix, nil, nil) != want {
			t.Fatal(suffix, want)
		}
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/999/datasets/%d/reconstruction/%d/steps/1/review", d.ID, id), nil, nil) != 404 {
		t.Fatal("cross-network review exposed")
	}
	result.Sources.Inputs = nil
	old, err := s.PutReconstruction(ctx, d.ID, "log", result)
	if err != nil {
		t.Fatal(err)
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/%d/datasets/%d/reconstruction/%d/steps/1/review", d.NetworkID, d.ID, old), nil, nil) != 409 {
		t.Fatal("source identity manufactured for old result")
	}
}
