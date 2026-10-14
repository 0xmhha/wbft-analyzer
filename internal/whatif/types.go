// Package whatif records counterfactual executions separately from source facts.
package whatif

const Version = "wbft-timer-experiment/1"
const Model = "recorded-external-slots/zero-generated-processing/recorded-signing-results/1"

// Source identifies evidence in the retained input, never a generated slot.
// Decimal strings preserve source coordinates across browser clients.
type Source struct {
	Writer  string `json:"writer_run"`
	Engine  string `json:"engine_run"`
	Step    string `json:"step"`
	Ordinal string `json:"ordinal"`
}

// State is the actual post-execution view. A stopped core has no view.
type State struct {
	Running bool    `json:"running"`
	Height  *string `json:"height"`
	Round   *string `json:"round"`
	Name    string  `json:"state,omitempty"`
}

type Answer struct {
	Writer string `json:"writer_run"`
	Engine string `json:"engine_run"`
	Step   string `json:"step"`
	Call   int    `json:"call"`
	Kind   int    `json:"kind"`
	Key    string `json:"-"`
}

type Question struct {
	Source Source `json:"source_input"`
	Output string `json:"output"`
}

// Step is keyed by execution order, independently of source record order.
// It contains bounded metadata; input bytes and block hashes remain outside it.
type Step struct {
	Actions         []Action   `json:"output_actions" nullable:"true"`
	RecordedActions []Action   `json:"recorded_output_actions" nullable:"true"`
	ParentOutput    string     `json:"parent_output"`
	Answers         []Answer   `json:"answer_sources"`
	Execution       string     `json:"execution_step"`
	Mono            string     `json:"t_mono_ns"`
	State           State      `json:"execution_state"`
	Source          *Source    `json:"source_input"`
	Cause           *Source    `json:"cause"`
	Parent          string     `json:"parent_execution_step"`
	Arm             *Source    `json:"timer_arm"`
	ArmExecution    string     `json:"timer_arm_execution_step"`
	Deadline        *string    `json:"timer_deadline_mono_ns"`
	Signing         *Source    `json:"signing_evidence"`
	Questions       []Question `json:"application_question_sources"`
	Generated       bool       `json:"generated"`
	Suppression     string     `json:"suppression_reason"`
	Input           string     `json:"input"`
	Digest          string     `json:"out_digest"`
	Outputs         int        `json:"outputs"`
	Comparable      bool       `json:"comparable"`
	Match           bool       `json:"match"`
	Counterfactual  bool       `json:"counterfactual"`
	Model           string     `json:"execution_model"`
}
