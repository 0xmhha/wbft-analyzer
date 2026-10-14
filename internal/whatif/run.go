package whatif

import "strconv"

type Scope struct {
	Writer    string `json:"writer_run"`
	Engine    string `json:"engine_run"`
	Execution string `json:"execution_step"`
	Mono      string `json:"horizon_mono_ns"`
	Internal  int    `json:"pending_internal"`
	Queued    int    `json:"queued_timers"`
	Armed     int    `json:"armed_timers"`
}

// Summary retains the bounded horizon and explicit failure classification.
// Completion means the supplied source ended, never a new network future.
type Summary struct {
	RetiredTimers     []Source `json:"replaced_original_timers" nullable:"true"`
	Version           string   `json:"version"`
	Model             string   `json:"execution_model"`
	Status            string   `json:"status"`
	Issue             string   `json:"issue,omitempty"`
	BaselineValidated bool     `json:"baseline_validated"`
	TimerValidated    bool     `json:"timer_trace_validated"`
	HelperVersion     string   `json:"helper_version"`
	SourceVersions    []string `json:"source_versions"`
	Steps             int64    `json:"steps"`
	Generated         int64    `json:"generated_steps"`
	SourceSteps       int64    `json:"source_steps"`
	Scopes            []Scope  `json:"scopes"`
	FailureParent     *string  `json:"failure_parent_execution_step,omitempty"`
	FailureOutput     *string  `json:"failure_parent_output,omitempty"`
	FailureCause      *Source  `json:"failure_cause,omitempty"`
	FailureSource     *Source  `json:"failure_source_input,omitempty"`
	FailureExecution  *string  `json:"failure_execution_step,omitempty"`
	Horizon           string   `json:"horizon"`
	FutureTail        bool     `json:"future_tail_generated"`
}

func ValidateScopes(scopes []Scope, total uint64) error {
	if len(scopes) == 0 || len(scopes) > 100000 {
		return ErrEvidence
	}
	seen := map[string]bool{}
	for _, scope := range scopes {
		if !sourceValid(&Source{Writer: scope.Writer, Engine: scope.Engine, Step: "1", Ordinal: "1"}) || !decimal(scope.Execution, false, 64) || !decimal(scope.Mono, true, 63) || scope.Internal < 0 || scope.Internal > 100000 || scope.Queued < 0 || scope.Queued > 100000 || scope.Armed < 0 || scope.Armed > 3 {
			return ErrEvidence
		}
		execution, err := strconv.ParseUint(scope.Execution, 10, 64)
		if err != nil || execution > total {
			return ErrEvidence
		}
		key := scope.Writer + "/" + scope.Engine
		if seen[key] {
			return ErrEvidence
		}
		seen[key] = true
	}
	return nil
}
