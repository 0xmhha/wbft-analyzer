// Package whatifjob runs retained timer experiments independently of source facts.
package whatifjob

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
)

var ErrRun = errors.New("timer experiment failed")

type Options struct {
	JobID                                            int64
	JobOwner                                         string
	Helper                                           *reexec.Helper
	ExpectedInputSHA, ExpectedNode, ExpectedChainSHA string
	OnBegin                                          func(int64) error
	Dataset                                          int64
	Input, Chain                                     string
	Policy                                           whatif.Policy
}
type Result struct {
	ID      int64          `json:"id"`
	Summary whatif.Summary `json:"summary"`
}

// Run holds a dataset lease, snapshots exact retained bytes and preserves
// explicit partial failures. Only validated metadata crosses the store boundary.
func Run(ctx context.Context, s *store.Store, o Options) (Result, error) {
	var result Result
	if o.Dataset < 1 || o.Policy.Validate() != nil {
		return result, whatif.ErrEvidence
	}
	release, err := s.DatasetReadLease(ctx, o.Dataset)
	if err != nil {
		return result, err
	}
	defer release()
	dataset, network, err := s.ReexecDataset(ctx, o.Dataset)
	if err != nil {
		return result, err
	}
	inputs, err := s.MessageInputs(ctx, o.Dataset)
	if err != nil {
		return result, err
	}
	var input messages.Summary
	for _, candidate := range inputs {
		if candidate.Summary.ID == o.Input {
			input = candidate.Summary
		}
	}
	if input.ID == "" || input.Kind != "journal" || o.ExpectedInputSHA != "" && (o.ExpectedInputSHA != input.SHA256 || o.ExpectedNode != input.Node) {
		return result, whatif.ErrEvidence
	}
	refs, err := s.InputFiles(ctx, o.Dataset, o.Input)
	if err != nil {
		return result, err
	}
	dir, err := reexec.Snapshot(ctx, input, refs)
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(dir)
	if len(refs) == 0 {
		return result, whatif.ErrEvidence
	}
	storage, err := s.InputStorageDirectory(ctx, o.Dataset)
	if errors.Is(err, store.ErrNotFound) {
		storage = filepath.Dir(refs[0].Path)
	} else if err != nil {
		return result, err
	}
	chain, err := reexec.RetainChain(ctx, o.Chain, storage)
	if err != nil {
		return result, err
	}
	if o.ExpectedChainSHA != "" && o.ExpectedChainSHA != chain.SHA256 {
		return result, whatif.ErrEvidence
	}
	chainFile := filepath.Join(dir, "chain.rlp")
	if err = reexec.CopyObject(ctx, chain, chainFile); err != nil {
		return result, err
	}
	journalDir := filepath.Join(dir, "journal")
	if err = os.Mkdir(journalDir, 0700); err != nil {
		return result, err
	}
	for _, file := range input.Files {
		if err = os.Rename(filepath.Join(dir, file.Name), filepath.Join(journalDir, file.Name)); err != nil {
			return result, err
		}
	}
	raw, err := os.ReadFile(chainFile)
	if err != nil || len(raw) > 64<<20 {
		return result, whatif.ErrEvidence
	}
	chainBlocks, err := sim.DecodeChain(raw)
	if err != nil {
		return result, err
	}
	if len(chainBlocks) == 0 || chainBlocks[0] == nil || chainBlocks[0].Header == nil || !strings.EqualFold(codec.BlockHash(chainBlocks[0].Header).Hex(), network.GenesisHash) {
		return result, whatif.ErrEvidence
	}
	prepared := messages.Prepared{Input: messages.Input{ID: input.ID, Kind: "journal", Node: input.Node, Path: journalDir}, Summary: input}
	if _, err = messages.Read(ctx, prepared, network.ChainID, network.GenesisHash, func(messages.Record) error { return nil }); err != nil {
		return result, err
	}
	blocks, err := sim.NewChainSource(chainBlocks)
	if err != nil {
		return result, err
	}
	evidence, err := whatif.InspectEvidence(ctx, journalDir, blocks)
	if err != nil {
		return result, err
	}
	bindings, networkScope, err := inspectNetwork(ctx, s, dataset, network, inputs, prepared, evidence)
	if err != nil {
		return result, err
	}
	planner := evidence.NewNetworkPlanner(bindings, networkScope)
	executable, err := os.Executable()
	if err != nil {
		return result, err
	}
	if o.Helper != nil {
		executable = o.Helper.Path
	}
	helperVersion, helperHash, err := reexec.ExecutableIdentity(executable)
	if err != nil {
		return result, err
	}
	if o.Helper != nil && helperHash != o.Helper.ExpectedSHA {
		return result, whatif.ErrEvidence
	}
	summary := whatif.Summary{Version: whatif.Version, Model: whatif.Model, Status: "running", BaselineValidated: true, HelperVersion: helperVersion, SourceVersions: evidence.Versions, RetiredTimers: evidence.RetiredTimers(), Network: &whatif.NetworkSummary{Version: whatif.NetworkVersion, Status: "running", Scope: networkScope}}
	record := store.WhatifRun{Dataset: o.Dataset, Input: o.Input, ChainSHA: chain.SHA256, SourceSHA: input.SHA256, HelperSHA: helperHash, Policy: o.Policy, Summary: summary}
	var id int64
	if o.JobID != 0 {
		id, err = s.BeginWhatifJob(ctx, o.JobID, o.JobOwner, record, chain.Path)
	} else {
		id, err = s.BeginWhatif(ctx, record, chain.Path)
	}
	if err != nil {
		return result, err
	}
	result.ID = id
	if err = s.PutWhatifNetworkBindings(ctx, id, bindings); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		summary.Status = "failed"
		summary.Issue = "network_evidence_unavailable"
		if finishErr := s.FinishWhatif(cleanup, id, summary); finishErr != nil {
			return result, finishErr
		}
		return result, err
	}
	if o.OnBegin != nil {
		if err = o.OnBegin(id); err != nil {
			summary.Status = "failed"
			summary.Issue = "job_link_failed"
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if finishErr := s.FinishWhatif(cleanup, id, summary); finishErr != nil {
				return result, finishErr
			}
			return result, err
		}
	}
	reader, writer := io.Pipe()
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	completed := make(chan error, 1)
	go func() {
		var err error
		if o.Helper == nil {
			err = whatif.ServeTimed(child, journalDir, chainFile, 1, o.Policy, json.NewEncoder(writer))
		} else {
			err = runHelper(child, *o.Helper, journalDir, chainFile, o.Policy, writer)
		}
		_ = writer.CloseWithError(err)
		completed <- err
	}()
	scanner := bufio.NewScanner(io.LimitReader(reader, (64<<20)+1))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	previous := uint64(0)
	var generated, sourced uint64
	terminal := false
	for scanner.Scan() {
		if err = ctx.Err(); err != nil {
			break
		}
		var header struct {
			Type      string         `json:"type"`
			ID        uint64         `json:"id"`
			Code      string         `json:"code"`
			Execution *string        `json:"execution_step"`
			Parent    *string        `json:"parent_execution_step"`
			Output    *string        `json:"parent_output"`
			Cause     *whatif.Source `json:"cause"`
			Source    *whatif.Source `json:"source_input"`
		}
		if json.Unmarshal(scanner.Bytes(), &header) != nil || header.ID != 1 || terminal {
			err = whatif.ErrEvidence
			break
		}
		switch header.Type {
		case "timed_step":
			step, decodeErr := whatif.DecodeStep(scanner.Bytes(), previous)
			if decodeErr != nil {
				err = decodeErr
				break
			}
			if err = evidence.Validate(step, previous); err != nil {
				break
			}
			step.SourceWall = evidence.RecordedSourceWall(step)
			effects, effectErr := planner.Note(step)
			if effectErr != nil {
				err = effectErr
				break
			}
			if err = s.PutWhatifStepWithEffects(ctx, id, step, effects); err != nil {
				break
			}
			previous++
			if step.Generated {
				generated++
			} else {
				sourced++
			}
			summary.TimerValidated = true
		case "timed_done":
			var done struct {
				Steps          string         `json:"steps"`
				Generated      string         `json:"generated_steps"`
				Source         string         `json:"source_steps"`
				Counterfactual bool           `json:"counterfactual"`
				Policy         whatif.Policy  `json:"timer_policy"`
				Model          string         `json:"execution_model"`
				Validated      bool           `json:"timer_trace_validated"`
				Horizon        string         `json:"horizon"`
				Future         bool           `json:"future_tail_generated"`
				Scopes         []whatif.Scope `json:"scopes"`
			}
			if json.Unmarshal(scanner.Bytes(), &done) != nil || !done.Counterfactual || done.Generated != strconv.FormatUint(generated, 10) || done.Source != strconv.FormatUint(sourced, 10) || done.Steps != strconv.FormatUint(previous, 10) || done.Model != whatif.Model || !done.Validated || done.Future || done.Horizon != "recorded_source_end" || len(done.Scopes) == 0 {
				err = whatif.ErrEvidence
				break
			}
			_, actualPolicy, policyErr := done.Policy.Canonical()
			_, expectedPolicy, _ := o.Policy.Canonical()
			if policyErr != nil || actualPolicy != expectedPolicy || whatif.ValidateScopes(done.Scopes, previous) != nil || evidence.Complete() != nil {
				err = whatif.ErrEvidence
				break
			}
			terminal = true
			summary.Status = "completed"
			summary.TimerValidated = true
			summary.Horizon = done.Horizon
			summary.Scopes = done.Scopes
		case "error":
			switch header.Code {
			case "signing_unavailable", "env_exhausted", "reservation_unavailable", "timing_unavailable", "answer_limit", "input_gap", "timer_policy", "replay_error":
			default:
				err = whatif.ErrEvidence
			}
			if err != nil {
				break
			}
			terminal = true
			summary.Status = "failed"
			if previous > 0 {
				summary.Status = "partial"
			}
			summary.Issue = header.Code
			if header.Execution != nil {
				if err = evidence.ValidateFailure(*header.Execution, header.Parent, header.Output, header.Cause, header.Source, previous, header.Code); err != nil {
					break
				}
			}
			summary.FailureExecution = header.Execution
			summary.FailureParent = header.Parent
			summary.FailureOutput = header.Output
			summary.FailureCause = header.Cause
			summary.FailureSource = header.Source
		default:
			err = whatif.ErrEvidence
		}
		if err != nil {
			break
		}
	}
	if err == nil {
		err = scanner.Err()
	}
	_ = reader.Close()
	cancel()
	childErr := <-completed
	if err == nil {
		err = childErr
	}
	if !terminal && err == nil {
		err = whatif.ErrEvidence
	}
	if err != nil {
		summary.Status = "failed"
		summary.Issue = "evidence_unavailable"
		if previous > 0 {
			summary.Status = "partial"
		}
	}
	cleanup, finish := context.WithTimeout(context.Background(), 10*time.Second)
	defer finish()
	remaining, networkSummary, networkErr := planner.Finish(summary.Status == "completed", bindings)
	if networkErr != nil {
		return result, networkErr
	}

	summary.Network = &networkSummary
	if finishErr := s.FinishWhatifWithNetwork(cleanup, id, summary, remaining); finishErr != nil {
		return result, finishErr
	}
	stored, readErr := s.WhatifRun(cleanup, o.Dataset, id)
	if readErr != nil {
		return result, readErr
	}
	result.Summary = stored.Summary
	if err != nil || summary.Status != "completed" {
		return result, ErrRun
	}
	return result, nil
}
