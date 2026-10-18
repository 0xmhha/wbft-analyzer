package reconstruct

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

const ReviewFormat = "wbft-reconstruction-review/1"

var ErrReview = errors.New("reconstructed review source metadata unavailable")
var reviewFrameName = regexp.MustCompile(`^frames-[A-Za-z0-9_.-]{1,128}\.jsonl$`)

type ReviewNetwork struct {
	ChainID string `json:"chain_id"`
	Genesis string `json:"genesis_hash"`
}
type ReviewHeight struct {
	Height string   `json:"height"`
	Status string   `json:"status"`
	Issues []string `json:"issues"`
}
type ReviewSource struct {
	LogSHA               string   `json:"log_sha256"`
	LogProfile           string   `json:"log_profile"`
	LogProfileSHA        string   `json:"log_profile_sha256"`
	LogNormalizer        string   `json:"log_normalizer"`
	ProcessingSHA        string   `json:"processing_sha256"`
	ProcessingFormat     string   `json:"processing_format"`
	ProcessingNormalizer string   `json:"processing_normalizer"`
	ProcessingRun        string   `json:"processing_run"`
	ProcessingInstance   string   `json:"processing_instance"`
	FrameRun             string   `json:"frame_run"`
	FrameSHA             string   `json:"frame_sha256"`
	ChainSHA             string   `json:"chain_sha256"`
	GenesisSHA           string   `json:"genesis_sha256"`
	BinarySHA            string   `json:"binary_sha256"`
	SourceCommit         string   `json:"source_commit"`
	CaptureComplete      bool     `json:"capture_complete"`
	CaptureIssues        []string `json:"capture_issues"`
}
type ReviewPacket struct {
	Format               string        `json:"format"`
	Classification       string        `json:"classification"`
	SpecificationVerdict string        `json:"specification_verdict"`
	ResultSHA            string        `json:"result_sha256"`
	ExecutionVersion     string        `json:"execution_version"`
	ComparisonModel      string        `json:"comparison_model"`
	CoreVersion          string        `json:"core_version"`
	AllImprovementsOff   bool          `json:"all_improvements_off"`
	Network              ReviewNetwork `json:"network"`
	Node                 string        `json:"node"`
	Height               ReviewHeight  `json:"height"`
	LogRun               string        `json:"log_run"`
	Position             int64         `json:"position"`
	Source               ReviewSource  `json:"source"`
	Step                 ExecutionStep `json:"step"`
}

// ExecutionReview selects the same one-based comparison position used by
// storage. The parent identity hashes the compact typed execution result.
func ExecutionReview(result ExecutionResult, position int64) (ReviewPacket, error) {
	if position < 1 {
		return ReviewPacket{}, ErrReview
	}
	var cursor int64
	for _, execution := range result.Executions {
		for _, step := range execution.Steps {
			cursor++
			if cursor != position {
				continue
			}
			raw, err := json.Marshal(result)
			if err != nil || len(raw) > maxExecutionJSON {
				return ReviewPacket{}, ErrReview
			}
			hash := sha256.Sum256(raw)
			return ReviewStep(result, hex.EncodeToString(hash[:]), position, execution.Height, execution.Run, step)
		}
	}
	return ReviewPacket{}, ErrReview
}

// ReviewStep transfers one selected stored comparison, not a native journal
// record or a conformance verdict. The parent checksum does not authenticate
// this packet independently of the original complete result.
func ReviewStep(summary ExecutionResult, parentSHA string, position int64, height, run string, step ExecutionStep) (ReviewPacket, error) {
	if summary.ExecutionVersion != ExecutionVersion || summary.ComparisonModel != ComparisonModel || !summary.AllImprovementsOff || !shaPattern.MatchString(parentSHA) || position < 1 || summary.Sources.Inputs == nil || summary.Sources.Frames == nil || step.Input.Height != height {
		return ReviewPacket{}, ErrReview
	}
	var selected *Height
	for i := range summary.Heights {
		if summary.Heights[i].Height == height {
			selected = &summary.Heights[i]
			break
		}
	}
	found := false
	for _, execution := range summary.Executions {
		if execution.Height == height && execution.Run == run {
			found = true
		}
	}
	if selected == nil || !found || selected.Issues == nil {
		return ReviewPacket{}, ErrReview
	}
	s, capture := summary.Sources, summary.Sources.Inputs
	if capture.Unavailable == nil || capture.GenesisSHA != s.GenesisSHA || step.Input.Source.Kind != "processing_boundary" || step.Input.Source.Run != capture.Run || step.Input.ObservationInstance == "" || step.Issues == nil || step.Observed == nil || step.Computed == nil || step.Differences == nil {
		return ReviewPacket{}, ErrReview
	}
	if selected.Status == "complete" && (!capture.CaptureComplete || len(capture.Unavailable) != 0 || !step.CoreApplied || len(step.Issues) != 0) {
		return ReviewPacket{}, ErrReview
	}
	p := ReviewPacket{Format: ReviewFormat, Classification: "cross_implementation_candidate", SpecificationVerdict: "not_evaluated", ResultSHA: parentSHA, ExecutionVersion: summary.ExecutionVersion, ComparisonModel: summary.ComparisonModel, CoreVersion: summary.CoreVersion, AllImprovementsOff: true, Network: ReviewNetwork{ChainID: summary.ChainID, Genesis: summary.GenesisHash}, Node: summary.Node, Height: ReviewHeight{Height: height, Status: selected.Status, Issues: selected.Issues}, LogRun: run, Position: position, Step: step,
		Source: ReviewSource{LogSHA: s.LogSHA, LogProfile: s.LogProfile, LogProfileSHA: s.LogProfileSHA, LogNormalizer: s.LogNormalizer, ProcessingSHA: capture.SHA256, ProcessingFormat: capture.Format, ProcessingNormalizer: capture.Normalizer, ProcessingRun: capture.Run, ProcessingInstance: step.Input.ObservationInstance, FrameRun: capture.FrameRun, FrameSHA: s.Frames.SHA256, ChainSHA: s.ChainSHA, GenesisSHA: s.GenesisSHA, BinarySHA: capture.BinarySHA, SourceCommit: capture.SourceCommit, CaptureComplete: capture.CaptureComplete, CaptureIssues: capture.Unavailable}}
	for _, sum := range []string{p.Source.LogSHA, p.Source.LogProfileSHA, p.Source.ProcessingSHA, p.Source.FrameSHA, p.Source.ChainSHA, p.Source.GenesisSHA, p.Source.BinarySHA} {
		if !shaPattern.MatchString(sum) {
			return ReviewPacket{}, ErrReview
		}
	}
	if !reviewPointers(p) {
		return ReviewPacket{}, ErrReview
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil || len(raw)+1 > 512<<10 {
		return ReviewPacket{}, ErrReview
	}
	return p, nil
}

func reviewPointers(p ReviewPacket) bool {
	valid := func(at Point) bool {
		if at.Line < 1 || at.BlockIndex != "" {
			return false
		}
		switch at.Kind {
		case "processing_boundary":
			return at.File == "input_observations" && at.Run == p.Source.ProcessingRun
		case "application_answer":
			return at.File == "input_observations" && (at.Run == "" || at.Run == p.Source.ProcessingRun)
		case "log":
			return at.File == "log" && at.Run == p.LogRun
		case "frame":
			return reviewFrameName.MatchString(at.File) && at.Run == p.Source.FrameRun
		default:
			return false
		}
	}
	input := p.Step.Input
	if !valid(input.Source) {
		return false
	}
	for _, point := range []*Point{input.Head, input.Application, input.TimerArm} {
		if point != nil && !valid(*point) {
			return false
		}
	}
	if input.Content != nil && !valid(input.Content.Source) {
		return false
	}
	projections := append(append([]Projection{}, p.Step.Observed...), p.Step.Computed...)
	for _, difference := range p.Step.Differences {
		if difference.Expected != nil {
			projections = append(projections, *difference.Expected)
		}
		if difference.Actual != nil {
			projections = append(projections, *difference.Actual)
		}
	}
	for _, projection := range projections {
		if projection.Source != nil && !valid(*projection.Source) {
			return false
		}
	}
	return true
}
