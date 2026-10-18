package reconstruct

import "github.com/0xmhha/wbft-analyzer/internal/source/inputobs"

const ExecutionVersion = "wbft-reconstructed-execution/1"

// Projection describes only observable, comparable output fields. It never
// embeds a core message, proposal, signature or an arbitrary event field map.
type Projection struct {
	Method          string               `json:"method,omitempty"`
	ArgumentSHA256  string               `json:"argument_sha256,omitempty"`
	Running         *bool                `json:"running,omitempty"`
	Valset          string               `json:"valset_digest,omitempty"`
	Parameters      *inputobs.Parameters `json:"parameters,omitempty"`
	Kind            string               `json:"kind"`
	Code            string               `json:"code,omitempty"`
	Height          string               `json:"height,omitempty"`
	Round           string               `json:"round,omitempty"`
	Digest          string               `json:"digest,omitempty"`
	State           string               `json:"state,omitempty"`
	DurationNS      string               `json:"duration_ns,omitempty"`
	DurationSeconds string               `json:"duration_seconds,omitempty"`
	Timer           string               `json:"timer,omitempty"`
	Proposer        string               `json:"proposer,omitempty"`
	Source          *Point               `json:"source,omitempty"`
}

type ReconstructedInput struct {
	ContentModel        string               `json:"content_model,omitempty"`
	Via                 string               `json:"via"`
	ProcessingMonoNS    string               `json:"processing_mono_ns,omitempty"`
	ObservationInstance string               `json:"observation_instance,omitempty"`
	DerivedTimerGen     string               `json:"derived_timer_generation,omitempty"`
	Ordinal             string               `json:"ordinal"`
	Kind                string               `json:"kind"`
	Height              string               `json:"height"`
	Round               string               `json:"round"`
	Source              Point                `json:"source"`
	Content             *ProcessingCandidate `json:"content,omitempty"`
	Head                *Point               `json:"head,omitempty"`
	Application         *Point               `json:"application,omitempty"`
	TimerArm            *Point               `json:"timer_arm,omitempty"`
	ReceiveClock        string               `json:"receive_clock,omitempty"`
}

type DifferenceCandidate struct {
	Kind     string      `json:"kind"`
	Expected *Projection `json:"expected,omitempty"`
	Actual   *Projection `json:"actual,omitempty"`
}

// ExecutionStep uses a reconstructed ordinal, not a native journal step.
type ExecutionStep struct {
	CoreApplied bool                  `json:"core_applied"`
	Issues      []string              `json:"issues"`
	Input       ReconstructedInput    `json:"input"`
	Observed    []Projection          `json:"observed"`
	Computed    []Projection          `json:"computed"`
	Differences []DifferenceCandidate `json:"difference_candidates"`
}

type HeightExecution struct {
	Height      string          `json:"height"`
	Run         string          `json:"log_run"`
	Status      string          `json:"status"`
	Issues      []string        `json:"issues"`
	Steps       []ExecutionStep `json:"steps"`
	Differences int64           `json:"difference_candidates"`
}

type ExecutionResult struct {
	Assessment
	ExecutionVersion   string            `json:"execution_version"`
	CoreVersion        string            `json:"core_version"`
	AllImprovementsOff bool              `json:"all_improvements_off"`
	ComparisonModel    string            `json:"comparison_model"`
	Executions         []HeightExecution `json:"executions"`
}
