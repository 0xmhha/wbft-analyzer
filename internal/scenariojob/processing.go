package scenariojob

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/inputlog"
)

// inspectProcessingTimings reuses the verified input/capture decoder, with
// independent before/after fingerprints. No path or input bytes enter output.
func inspectProcessingTimings(ctx context.Context, p messages.Prepared, chain, chainID, genesis string, from, to uint64, horizon time.Duration) (scenario.ProcessingTimings, error) {
	source := scenario.Input{ID: p.Summary.ID, Kind: p.Summary.Kind, Node: p.Summary.Node, SHA256: p.Summary.SHA256}
	before, err := messages.Fingerprint(ctx, p.Input)
	if err != nil || before.SHA256 != source.SHA256 {
		return scenario.ProcessingTimings{}, errors.New("processing source fingerprint mismatch")
	}
	plan, err := reexec.Inspect(ctx, p, chain, chainID, genesis, from, to)
	if err != nil {
		return scenario.ProcessingTimings{}, err
	}
	after, err := messages.Fingerprint(ctx, p.Input)
	if err != nil || after.SHA256 != before.SHA256 {
		return scenario.ProcessingTimings{}, errors.New("processing source changed during inspection")
	}
	return processingTimingsFromPlan(source, from, to, horizon, plan)
}

func processingTimingsFromPlan(source scenario.Input, from, to uint64, horizon time.Duration, plan reexec.Plan) (scenario.ProcessingTimings, error) {
	out := scenario.ProcessingTimings{Source: source, Status: "complete", Scope: "recorded_core_head_plus_one", From: from, To: to, Samples: []scenario.ProcessingSample{}, Excluded: []scenario.ProcessingExcluded{}, Assumptions: []string{
		"measured_core_step_envelope_not_internal_execution_milestones",
		"monotonic_entry_and_completion_from_one_writer_and_engine_generation",
		"no_measured_receive_check_interval_in_step_records",
		"lifecycle_and_wal_replay_intervals_are_not_service_samples",
	}}
	if !logs.Identifier(source.ID) || source.Kind != "journal" || source.Node == "" || len(source.SHA256) != 64 || from < 1 || to < from || to-from >= 10000 || horizon <= 0 || horizon > 24*time.Hour || len(plan.Steps) > reexec.MaxSteps || plan.JournalIssue != "" {
		return out, errors.New("unproved processing timing source")
	}
	if _, err := hex.DecodeString(source.SHA256); err != nil || strings.ToLower(source.SHA256) != source.SHA256 || plan.From != from || plan.To != to || plan.Input.Summary.ID != source.ID || plan.Input.Summary.Kind != source.Kind || plan.Input.Summary.Node != source.Node || plan.Input.Summary.SHA256 != source.SHA256 {
		return out, errors.New("processing plan identity mismatch")
	}
	var ordinal int64
	for _, step := range plan.Steps {
		if step.Ordinal <= ordinal || !logs.Identifier(step.Run) || len(step.File) != 24 || !strings.HasSuffix(step.File, ".wal") {
			return out, errors.New("invalid processing source coordinates")
		}
		if _, err := strconv.ParseUint(step.File[:20], 10, 64); err != nil {
			return out, errors.New("invalid processing source file")
		}
		ordinal = step.Ordinal
		point := scenario.ProcessingPoint{Ordinal: step.Ordinal, File: step.File, Run: step.Run, Engine: step.Engine, Step: step.Number, Height: step.Height}
		exclude := func(reason string, incomplete bool) {
			out.Excluded = append(out.Excluded, scenario.ProcessingExcluded{Point: point, Kind: step.Input, Reason: reason})
			if incomplete {
				out.Status = "partial"
			}
		}
		if step.Input == inputlog.KindStart || step.Input == inputlog.KindStop {
			exclude("lifecycle_not_service_costed", false)
			continue
		}
		if step.Warmup || step.InputVia == "wal" {
			exclude("replay_or_warmup_not_service_costed", false)
			continue
		}
		h, err := strconv.ParseUint(step.Height, 10, 64)
		if err != nil || strconv.FormatUint(h, 10) != step.Height {
			return out, errors.New("invalid processing height scope")
		}
		if h < from || h > to {
			exclude("height_outside_scope", false)
			continue
		}
		if step.InputVia == "" || step.InputVia == "unknown" {
			exclude("input_route_unavailable", true)
			continue
		}
		if step.Completeness != "complete" {
			exclude("input_witness_unavailable", true)
			continue
		}
		engine, engineErr := strconv.ParseUint(step.Engine, 10, 64)
		number, stepErr := strconv.ParseUint(step.Number, 10, 64)
		if engineErr != nil || stepErr != nil || engine == 0 || number == 0 || strconv.FormatUint(engine, 10) != step.Engine || strconv.FormatUint(number, 10) != step.Number {
			exclude("engine_step_identity_unavailable", true)
			continue
		}
		if step.EntryMono == nil {
			exclude("measured_entry_unavailable", true)
			continue
		}
		entry, entryErr := strconv.ParseInt(*step.EntryMono, 10, 64)
		end, endErr := strconv.ParseInt(step.Mono, 10, 64)
		if entryErr != nil || endErr != nil || entry < 0 || end < entry || strconv.FormatInt(entry, 10) != *step.EntryMono || strconv.FormatInt(end, 10) != step.Mono || time.Duration(end-entry) > horizon {
			exclude("invalid_monotonic_interval", true)
			continue
		}
		kind, code := step.Input, uint64(0)
		if kind == inputlog.KindCapturedMessage {
			kind = inputlog.KindMessage
		}
		valid := true
		switch kind {
		case inputlog.KindMessage:
			switch step.Phase {
			case "PRE-PREPARE":
				code = uint64(codec.CodePreprepare)
			case "PREPARE":
				code = uint64(codec.CodePrepare)
			case "COMMIT":
				code = uint64(codec.CodeCommit)
			case "ROUND-CHANGE":
				code = uint64(codec.CodeRoundChange)
			default:
				valid = false
			}
		case inputlog.KindNewHead, inputlog.KindRequest, inputlog.KindBacklog, inputlog.KindTimeout, inputlog.KindCommitResult, inputlog.KindBroadcastFailed, inputlog.KindPeerConnected:
		default:
			valid = false
		}
		if !valid {
			exclude("work_class_unavailable", true)
			continue
		}
		out.Samples = append(out.Samples, scenario.ProcessingSample{Point: point, Kind: kind, Code: code, EntryMono: *step.EntryMono, CompleteMono: step.Mono, Nanoseconds: end - entry})
	}
	if len(out.Samples) == 0 {
		out.Status = "partial"
	}
	return out, nil
}
