package scenario

import (
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
)

const (
	DeclaredRuntimeModel = "declared-runtime"
	EmpiricalCoreModel   = "empirical-core"
)

func ValidModel(model string) bool {
	return model == "" || model == DeclaredRuntimeModel || model == EmpiricalCoreModel
}

// EmpiricalProjection describes an explicit simulation, independently of the
// observed physical executor. Its choices are hashed with the source model.
type EmpiricalProjection struct {
	Assumptions    []string           `json:"assumptions"`
	Nodes          []EmpiricalNode    `json:"nodes"`
	Timings        []EmpiricalTimings `json:"runtime_timings"`
	Application    AppTiming          `json:"application"`
	NativeExcluded []AppOutcome       `json:"native_excluded"`
	Runtimes       []Runtime          `json:"runtimes"`
}

type EmpiricalNode struct {
	Node              string `json:"node"`
	Substituted       bool   `json:"substituted"`
	Source            Input  `json:"source"`
	Options           Node   `json:"-"`
	Improvements      string `json:"improvements"`
	BacklogLimit      int    `json:"backlog_limit"`
	Profile           string `json:"profile"`
	ReplayWAL         bool   `json:"wal_replay"`
	OptionEvidence    string `json:"option_evidence"`
	RuntimeEvidence   string `json:"runtime_evidence"`
	SigningState      string `json:"signing_state"`
	ApplicationPolicy string `json:"application_policy"`
	ParameterEvidence string `json:"parameter_evidence"`
}

// fitEmpiricalProjection never changes the recorded node options, runtime
// bindings, or strict assessment. The substitution applies only to frame-only
// nodes with independently matched runtime configuration and lifecycle.
func fitEmpiricalProjection(o FitOptions, fitted Fitted, sources []Input) (EmpiricalProjection, []Issue, error) {
	out := EmpiricalProjection{
		Assumptions: []string{
			"manual_clock_and_fake_transport",
			"wall_clock_starts_at_recorded_origin",
			"receive_checks_and_core_steps_consume_no_simulated_time",
			"independent_request_fake_application_with_per_node_empirical_delays",
			"native_successful_builds_and_imports_condition_the_delay_distribution",
			"runtime_assembly_includes_cancelled_seals_but_not_sealing_or_delivery_time",
			"frame_only_nodes_use_wbft_core_with_all_improvements_off",
			"substitutes_use_fresh_test_key_state_at_genesis_and_no_wal_replay",
			"source_engine_intervals_bound_substitute_core_lifetime_only",
			"equal_time_lifecycle_events_keep_source_order",
			"transactions_and_source_executor_internals_are_not_executed",
			"system_contract_execution_replaced_by_recorded_epoch_candidates",
			"recorded_mid_run_engine_events_drive_core_controls",
		},
		Nodes: []EmpiricalNode{}, Timings: []EmpiricalTimings{},
		Application:    AppTiming{Build: append([]AppSample{}, fitted.App.Build...), Import: append([]AppSample{}, fitted.App.Import...), Unproved: fitted.App.Unproved, Policies: []ApplicationPolicy{}, Outcomes: []AppOutcome{}},
		NativeExcluded: []AppOutcome{}, Runtimes: []Runtime{},
	}
	issues := []Issue{}
	for _, outcome := range fitted.App.Outcomes {
		if outcome.Status != "submitted" {
			out.NativeExcluded = append(out.NativeExcluded, outcome)
		}
	}
	for _, observed := range fitted.NodeOptions {
		addr := strings.ToLower(observed.Address.Hex())
		node := EmpiricalNode{Node: addr, Options: observed, ApplicationPolicy: "independent_request_sampled_empty_body", ParameterEvidence: "unavailable", SigningState: "unavailable"}
		if observed.ProfileEvidence != "" {
			for _, input := range sources {
				if input.Kind == "journal" && strings.EqualFold(input.Node, addr) {
					node.Source = input
				}
			}
			node.ParameterEvidence = "journal_scope_parameters_verified"
			if observed.RuntimeEvidence != "verified" || observed.SignFloor != nil {
				issues = append(issues, Issue{Node: addr, Code: "native_runtime_policy_unavailable"})
			}
			found := false
			for _, runtime := range fitted.Runtimes {
				if !strings.EqualFold(runtime.Node, addr) {
					continue
				}
				found = true
				switch runtime.SignFloorState {
				case "none":
					node.SigningState = "recorded_none"
				case "recorded":
					node.SigningState = "recorded_floor_unsupported"
				}
				if runtime.EngineStopped && (runtime.EngineHistory == nil || runtime.EngineHistory.Status != "complete") || runtime.SignFloorState != "none" || runtime.SignFloor != nil {
					issues = append(issues, Issue{Node: addr, Code: "native_runtime_model_unavailable"})
				}
				out.Runtimes = append(out.Runtimes, scopeEmpiricalRuntime(runtime, o.Until))
			}
			if !found {
				issues = append(issues, Issue{Node: addr, Code: "native_runtime_unavailable"})
			}
		} else {
			node.Substituted = true
			node.SigningState = "fresh_test_keys_genesis_no_replay"
			node.Options.Profile = "compat"
			node.Options.ProfileEvidence = "modeled_core_substitution"
			node.Options.Improvements = 0
			node.Options.BacklogLimit = 0
			node.Options.ReplayWAL = false
			node.Options.RuntimeEvidence = "modeled_core_substitution"
			frames := 0
			for _, input := range sources {
				if input.Kind == "frames" && strings.EqualFold(input.Node, addr) {
					node.Source = input
					frames++
				}
			}
			if frames != 1 {
				issues = append(issues, Issue{Node: addr, Code: "substitute_frame_source_unavailable"})
			}
			found := false
			for _, input := range o.RuntimeObservations {
				if !strings.EqualFold(input.Source.Node, addr) {
					continue
				}
				found = true
				bound := false
				for _, binding := range fitted.RuntimeObservations {
					if binding.Source == input.Source && empiricalParametersVerified(binding) {
						bound = true
						node.ParameterEvidence = "static_wbft_parameters_verified"
					}
				}
				if !bound {
					issues = append(issues, Issue{Node: addr, Code: "substitute_configuration_unverified"})
				}
				timing, err := FitEmpiricalTimings(input, o.From, o.To, o.Until)
				if err != nil {
					return out, nil, err
				}
				out.Timings = append(out.Timings, timing)
				out.Application.Build = append(out.Application.Build, timing.Build...)
				out.Application.Import = append(out.Application.Import, timing.Import...)
				runtime, err := fitSubstituteRuntime(input, o.Origin, o.Until)
				if err != nil {
					issues = append(issues, Issue{Node: addr, Code: "substitute_lifecycle_unavailable"})
				} else {
					out.Runtimes = append(out.Runtimes, runtime)
				}
			}
			if !found {
				issues = append(issues, Issue{Node: addr, Code: "substitute_runtime_source_unavailable"})
			}
		}
		node.Improvements = strconv.FormatUint(node.Options.Improvements, 10)
		node.BacklogLimit = node.Options.BacklogLimit
		node.Profile = node.Options.Profile
		node.ReplayWAL = node.Options.ReplayWAL
		node.OptionEvidence = node.Options.ProfileEvidence
		node.RuntimeEvidence = node.Options.RuntimeEvidence
		out.Nodes = append(out.Nodes, node)
	}
	return out, issues, nil
}

// Late shutdown records remain in the observed report but do not introduce
// events after the explicit simulation horizon.
func scopeEmpiricalRuntime(observed Runtime, until time.Duration) Runtime {
	out := observed
	out.Events = []RuntimeEvent{}
	for _, e := range observed.Events {
		if time.Duration(e.AtNS) <= until {
			out.Events = append(out.Events, e)
		}
	}
	return out
}

func fitSubstituteRuntime(in RuntimeObservation, origin time.Time, until time.Duration) (Runtime, error) {
	c := in.Capture
	off := false
	out := Runtime{Node: in.Source.Node, Input: in.Source.ID, ReplayWAL: &off, SignFloorState: "none", Events: []RuntimeEvent{}, WALPolicies: []WALPolicy{}}
	if !c.Complete || len(c.Engines) == 0 || origin.IsZero() {
		return out, errors.New("substitute lifecycle unavailable")
	}
	var previous time.Time
	seen := map[string]bool{}
	for _, engine := range c.Engines {
		if seen[engine.ID] || engine.ID == "" || engine.State != "observed_stopped" && engine.State != "observed_started" {
			return out, errors.New("ambiguous substitute lifecycle")
		}
		seen[engine.ID] = true
		stages := map[string]runtimeobs.Point{}
		for _, p := range engine.Stages {
			if p.ID != engine.ID || p.Type != "engine_stage" || p.Line < 1 || p.Line > len(c.Points) || !reflect.DeepEqual(p, c.Points[p.Line-1]) || stages[p.Stage].Line != 0 {
				return out, errors.New("substitute lifecycle source mismatch")
			}
			stages[p.Stage] = p
		}
		start, err := time.Parse(time.RFC3339Nano, stages["start_enter"].Wall)
		if err != nil || start.Before(origin) || !previous.IsZero() && start.Before(previous) {
			return out, errors.New("substitute lifecycle clock mismatch")
		}
		if start.Sub(origin) >= until {
			continue
		}
		if out.Starts == 0 {
			out.StartNS = int64(start.Sub(origin))
		} else {
			out.Events = append(out.Events, RuntimeEvent{Action: "restart", AtNS: int64(start.Sub(origin)), Run: c.Run, Line: int64(stages["start_enter"].Line)})
		}
		out.Starts++
		if engine.State == "observed_started" {
			if len(seen) != len(c.Engines) {
				return out, errors.New("overlapping substitute engines")
			}
			previous = time.Time{}
			continue
		}
		stop, err := time.Parse(time.RFC3339Nano, stages["stop_enter"].Wall)
		end, errEnd := time.Parse(time.RFC3339Nano, stages["stop_return"].Wall)
		if err != nil || errEnd != nil || stop.Before(start) || end.Before(stop) {
			return out, errors.New("substitute stop clock mismatch")
		}
		previous = end
		if stop.Sub(origin) <= until {
			out.Events = append(out.Events, RuntimeEvent{Action: "stop", AtNS: int64(stop.Sub(origin)), Run: c.Run, Line: int64(stages["stop_enter"].Line)})
		}
	}
	if out.Starts == 0 {
		return out, errors.New("no substitute engine in scope")
	}
	return out, nil
}

func assessEmpirical(projection EmpiricalProjection, links []Link, until time.Duration) Assessment {
	out := Assessment{Version: FitVersion, Status: "complete", Issues: []Issue{}}
	add := func(node, code string) { out.Issues = append(out.Issues, Issue{Node: node, Code: code}) }
	if len(links) != len(projection.Nodes)*(len(projection.Nodes)-1) {
		add("", "directed_links_missing")
	}
	for _, link := range links {
		if link.Status != "complete" || link.Loss == nil || len(link.Delays) == 0 {
			out.Issues = append(out.Issues, Issue{Link: link.Sender + "/" + link.Receiver, Code: "link_model_unavailable"})
		}
	}
	for _, node := range projection.Nodes {
		build, imports := 0, 0
		for _, sample := range projection.Application.Build {
			if strings.EqualFold(sample.Node, node.Node) {
				build++
			}
		}
		for _, sample := range projection.Application.Import {
			if strings.EqualFold(sample.Node, node.Node) {
				imports++
			}
		}
		if build == 0 || imports == 0 {
			add(node.Node, "node_application_model_unavailable")
		}
		for _, runtime := range projection.Runtimes {
			if strings.EqualFold(runtime.Node, node.Node) && (runtime.Starts == 0 || runtime.StartNS < 0 || time.Duration(runtime.StartNS) >= until) {
				add(node.Node, "runtime_outside_scope")
			}
		}
	}
	if projection.Application.Unproved > 0 {
		add("", "application_model_incomplete")
	}
	if len(out.Issues) > 0 {
		out.Status = "partial"
	}
	return out
}

func orderIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		if a.Link != b.Link {
			return a.Link < b.Link
		}
		return a.Code < b.Code
	})
}
