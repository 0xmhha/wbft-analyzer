package reconstruct

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func reviewFixture(t *testing.T) (ReviewPacket, ExecutionResult) {
	t.Helper()
	raw, err := os.ReadFile("testdata/review.json")
	if err != nil {
		t.Fatal(err)
	}
	var p ReviewPacket
	if err = json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	s := p.Source
	result := ExecutionResult{ExecutionVersion: p.ExecutionVersion, ComparisonModel: p.ComparisonModel, CoreVersion: p.CoreVersion, AllImprovementsOff: p.AllImprovementsOff,
		Assessment: Assessment{Version: Version, Node: p.Node, ChainID: p.Network.ChainID, GenesisHash: p.Network.Genesis, From: p.Height.Height, To: p.Height.Height, Heights: []Height{{Height: p.Height.Height, Status: p.Height.Status, Issues: p.Height.Issues}}, Sources: Sources{LogSHA: s.LogSHA, LogProfile: s.LogProfile, LogProfileSHA: s.LogProfileSHA, LogNormalizer: s.LogNormalizer, GenesisSHA: s.GenesisSHA, ChainSHA: s.ChainSHA, Frames: &messages.Summary{SHA256: s.FrameSHA}, Inputs: &InputObservationSummary{SHA256: s.ProcessingSHA, Format: s.ProcessingFormat, Normalizer: s.ProcessingNormalizer, Run: s.ProcessingRun, FrameRun: s.FrameRun, GenesisSHA: s.GenesisSHA, BinarySHA: s.BinarySHA, SourceCommit: s.SourceCommit, CaptureComplete: s.CaptureComplete, Unavailable: s.CaptureIssues}}}, Executions: []HeightExecution{{Height: p.Height.Height, Run: p.LogRun, Status: p.Height.Status, Issues: p.Height.Issues, Steps: []ExecutionStep{p.Step}}}}
	return p, result
}
func TestExecutionReviewUsesCanonicalParentIdentityAndComparisonPosition(t *testing.T) {
	p, result := reviewFixture(t)
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	got, err := ExecutionReview(result, 1)
	if err != nil || got.ResultSHA != hex.EncodeToString(sum[:]) || got.Step.Input.Source.Sequence != p.Step.Input.Source.Sequence || got.Step.Input.Ordinal != "4" || got.Position != 1 {
		t.Fatal(got, err)
	}
	for _, position := range []int64{-1, 0, 2} {
		if _, err := ExecutionReview(result, position); !errors.Is(err, ErrReview) {
			t.Fatal("nonexistent comparison exported", position, err)
		}
	}
}
func TestReviewStepPreservesVersionedFixtureAndCoordinateDomains(t *testing.T) {
	want, result := reviewFixture(t)
	got, err := ReviewStep(result, want.ResultSHA, want.Position, want.Height.Height, want.LogRun, want.Step)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	raw, err := json.Marshal(got)
	if err != nil || strings.Contains(string(raw), `"path"`) || strings.Contains(string(raw), `"payload"`) || got.SpecificationVerdict != "not_evaluated" {
		t.Fatal("unsafe review projection", err)
	}
}
func TestReviewStepRejectsMissingProvenanceAndPathInjection(t *testing.T) {
	for _, name := range []string{"input", "genesis", "scope", "path", "parent", "complete"} {
		t.Run(name, func(t *testing.T) {
			p, result := reviewFixture(t)
			switch name {
			case "input":
				result.Sources.Inputs = nil
			case "genesis":
				result.Sources.GenesisSHA = strings.Repeat("1", 64)
			case "scope":
				p.LogRun = "another"
			case "path":
				p.Step.Input.TimerArm.File = "/private/source"
			case "parent":
				p.ResultSHA = "unknown"
			case "complete":
				result.Heights[0].Status = "complete"
				result.Sources.Inputs.CaptureComplete = false
			}
			if _, err := ReviewStep(result, p.ResultSHA, p.Position, p.Height.Height, p.LogRun, p.Step); !errors.Is(err, ErrReview) {
				t.Fatal("unavailable review accepted", err)
			}
		})
	}
}
