package reexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

// Inspect uses two passes: asynchronous wire records may follow their steps.
// Explicit capture references bind new inputs; legacy inputs require a unique
// content/time witness, and weaker associations stay partial.
func Inspect(ctx context.Context, p messages.Prepared, chain, chainID, genesis string, from, to uint64) (Plan, error) {
	out := Plan{Answers: map[string]recordedAnswer{}, Contexts: map[int64]answerContext{}, From: from, To: to, Input: p, Chain: chain, SourceVersions: []string{}, Heights: []Height{}, Steps: []Step{}}
	if from < 1 || to < from || to-from >= 10000 {
		return out, errors.New("reexec height range must contain 1..10000 heights starting at 1 or later")
	}
	raw, err := readChain(chain)
	if err != nil {
		return out, err
	}
	hash := sha256.Sum256(raw)
	out.ChainSHA = hex.EncodeToString(hash[:])
	blocks, err := sim.DecodeChain(raw)
	if err != nil || len(blocks) == 0 || len(blocks) > 1000000 {
		return out, errors.New("invalid or oversized recorded chain")
	}
	if blocks[0] == nil || blocks[0].Header == nil || !strings.EqualFold(codec.BlockHash(blocks[0].Header).Hex(), genesis) {
		return out, errors.New("recorded chain genesis mismatch")
	}
	headers := map[string]bool{}
	headerHashes := map[string]string{}
	for i, b := range blocks {
		if b == nil || b.Header == nil || !b.Header.Number.IsUint64() || b.Header.Number.Big().Uint64() != uint64(i) {
			return out, errors.New("recorded chain is not consecutive canonical indices")
		}
		if i > 0 && b.Header.ParentHash != codec.BlockHash(blocks[i-1].Header) {
			return out, errors.New("recorded chain parent mismatch")
		}
		headers[b.Header.Number.String()] = true
		headerHashes[b.Header.Number.String()] = strings.ToLower(codec.BlockHash(b.Header).Hex())
	}
	_, readErr := messages.Read(ctx, p, chainID, genesis, func(messages.Record) error { return nil })
	if readErr != nil {
		out.JournalIssue = "damaged_journal"
	}
	rd, err := journal.OpenReader(nil, p.Input.Path)
	if err != nil {
		return out, err
	}
	wire := map[string]int{}
	exact := map[string]int{}
	versions := map[string]bool{}
	var coreFingerprint string
	run := ""
	var ordinal int64
	// No payload or configuration is retained in the plan.
	for {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		rec, e := rd.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			out.JournalIssue = "damaged_journal"
			break
		}
		ordinal++
		if ordinal > MaxRecords {
			return out, errors.New("journal record limit exceeded")
		}
		switch b := rec.Body.(type) {
		case *journal.SegmentRec:
			if !logs.Identifier(b.Run) {
				return out, errors.New("invalid journal writer run")
			}
			if b.Run != run {
				coreFingerprint = ""
			}
			run = b.Run
			versions[safeVersion(b.Commit)] = true
			cfg, _ := json.Marshal(b.Core)
			hash := sha256.Sum256(cfg)
			fingerprint := hex.EncodeToString(hash[:])
			if coreFingerprint != "" && coreFingerprint != fingerprint {
				out.JournalIssue = "changing_core_configuration"
			}
			coreFingerprint = fingerprint

		case *journal.MsgRec:
			if b.Dir == journal.In && len(b.Payload) <= 16<<20 && (b.Size == 0 || b.Size == uint64(len(b.Payload))) {
				payload, code, act, _ := transport.DecodeFrame(b.Code, b.Payload)
				if act == transport.FrameDeliver {
					wire[wireKey(run, code, payload)]++
					exact[exactWireKey(run, code, payload, b.Mono)]++
				}
			}
		}
	}
	for v := range versions {
		out.SourceVersions = append(out.SourceVersions, v)
	}
	sort.Strings(out.SourceVersions)
	rd, err = journal.OpenReader(nil, p.Input.Path)
	if err != nil {
		return out, err
	}
	run = ""
	ordinal = 0
	var deferredProfile, priorProfile bool
	var lastSeq, lastStep, engine uint64
	started, lost := false, false
	status := map[string]*Height{}
	for h := from; ; h++ {
		n := strconv.FormatUint(h, 10)
		status[n] = &Height{Number: n, Status: "not_possible", Issues: []string{"no_recorded_steps"}}
		if h == to {
			break
		}
	}
	for {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		rec, pos, e := rd.NextAt()
		if e == io.EOF {
			break
		}
		if e != nil {
			out.JournalIssue = "damaged_journal"
			break
		}
		ordinal++
		if seg, ok := rec.Body.(*journal.SegmentRec); ok {
			deferredProfile = seg.Core.NextHeight != nil && seg.Core.NextHeight.Validate() == nil
			priorProfile = consensus.ImprovementSet(seg.Core.Improvements).Has(consensus.BindPriorHead)
		}
		if seg, ok := rec.Body.(*journal.SegmentRec); ok && seg.Run != run {
			run = seg.Run
			lastSeq = 0
			lastStep, engine = 0, 0
			started = false
			lost = false
		}
		if rec.JSeq == 0 || lastSeq != 0 && rec.JSeq != lastSeq+1 {
			lost = true
		}
		lastSeq = rec.JSeq
		if _, ok := rec.Body.(*journal.GapRec); ok {
			lost = true
			out.JournalIssue = "journal_gap"
			continue
		}
		b, ok := rec.Body.(*journal.StepRec)
		if !ok {
			continue
		}
		if len(out.Steps) >= MaxSteps {
			return out, errors.New("journal step limit exceeded")
		}
		n := new(big.Int).Add(b.HeadNumber.Big(), big.NewInt(1)).String()
		step := Step{Ordinal: ordinal, File: fmt.Sprintf("%020d.wal", pos.Segment), Run: run, Engine: strconv.FormatUint(b.EngineRun, 10), Number: strconv.FormatUint(b.Step, 10), Height: n, Input: safeInput(b.InputKind), Recorded: strings.ToLower(b.OutDigest.Hex()), Class: "not_comparable", Completeness: "complete", Issues: []string{}}
		switch b.Via {
		case "internal", "app", "timer", "peer", "wal", "engine":
			step.InputVia = b.Via
		default:
			step.InputVia = "unknown"
		}

		if b.Entry != nil {
			value := strconv.FormatInt(int64(b.Entry.Mono), 10)
			step.EntryMono = &value
			step.EntryWall = time.Unix(0, b.Entry.WallNs).UTC().Format(time.RFC3339Nano)
		}
		step.Mono = strconv.FormatInt(int64(b.Mono), 10)
		step.Wall = time.Unix(0, b.WallNs).UTC().Format(time.RFC3339Nano)
		step.Offset = &pos.Offset
		step.ValsetDigest = strings.ToLower(b.ValsetDigest.Hex())
		if b.InputKind == inputlog.KindStart && b.Step == 1 {
			started = true
			lost = false
			engine = b.EngineRun
			lastStep = 0
		}
		if !started && lastStep == 0 {
			engine = b.EngineRun
		}
		if b.Step == 0 || b.EngineRun != engine || (lastStep != 0 && b.Step != lastStep+1) {
			lost = true
		}
		lastStep = b.Step
		if !started {
			markStep(&step, "not_possible", "missing_engine_start")
		}
		if lost {
			markStep(&step, "not_possible", "step_or_journal_gap")
		}
		if head, exists := headerHashes[b.HeadNumber.String()]; exists && head != strings.ToLower(b.HeadHash.Hex()) {
			markStep(&step, "not_possible", "head_identity")
		}
		if len(b.Input) > 16<<20 {
			markStep(&step, "partial", "payload")
		} else if b.InputKind == inputlog.KindDeferredMessage {
			if !deferredProfile {
				markStep(&step, "not_possible", "receive_profile_unavailable")
			}
			m, evidence, err := journal.InspectDeferred(rd, b.Input)
			if err != nil {
				markStep(&step, "partial", "input_decode")
			} else {
				decodedMessage(&step, m)
				step.DeferredOrigin = messages.ProjectDeferredEvidence(evidence)
			}
		} else if b.InputKind == inputlog.KindCapturedMessage {
			inspectCaptured(rd, run, b, &step)
		} else if decoded, e := inputlog.Decode(b.InputKind, b.Input, nil); e != nil {
			markStep(&step, "partial", "input_decode")
		} else if m, ok := decoded.(consensus.Message); ok {
			decodedMessage(&step, m)
			if b.Via == "peer" {
				k := wireKey(run, uint64(m.Code), m.Payload)
				x := exactWireKey(run, uint64(m.Code), m.Payload, m.RecvMono)
				if wire[k] == 0 {
					markStep(&step, "partial", "wire_payload")
				} else if exact[x] != 1 {
					markStep(&step, "partial", "wire_association")
				} else {
					wire[k]--
					exact[x]--
				}

			}
		}
		index, e := strconv.ParseUint(n, 10, 64)
		if e != nil || index == ^uint64(0) {
			markStep(&step, "not_possible", "unsupported_canonical_index")
		} else if !headers[strconv.FormatUint(index-1, 10)] || !headers[n] || !headers[strconv.FormatUint(index+1, 10)] {
			markStep(&step, "partial", "headers")
		}
		if out.JournalIssue != "" {
			markStep(&step, "not_possible", out.JournalIssue)
		}
		ctx := answerContext{run, step.Engine, b.HeadNumber.String(), strings.ToLower(b.HeadHash.Hex()), step.ValsetDigest}
		out.Contexts[ordinal] = ctx
		for i, raw := range b.Env {
			c, err := inputlog.DecodeEnv(raw)
			if err == nil && c.Kind == inputlog.EnvValidatorsAt && priorProfile {
				canonical, encodeErr := inputlog.EncodeEnv(c)
				if encodeErr != nil || !bytes.Equal(canonical, raw) || c.Result != 0 || c.Future != 0 || c.Step != "" || c.Class != "" || c.Bad || c.Validators != nil && c.Err != "" {
					markStep(&step, "partial", "authority_source")
				}
				// Authority records are consumed by the closed core reader.
				// They never become context-scoped application answers.
				continue
			}
			if err != nil || (c.Kind != inputlog.EnvValidateProposal && c.Kind != inputlog.EnvIsBadBlock) {
				markStep(&step, "partial", "application_answer")
				continue
			}
			if len(out.Answers) >= 100000 {
				return out, errors.New("application answer limit exceeded")
			}
			source := AnswerSource{Ordinal: ordinal, File: step.File, Run: run, Engine: step.Engine, Step: step.Number, Call: i + 1, Kind: int(c.Kind), Key: strings.ToLower(c.Key.Hex())}
			key := answerID(run, step.Engine, step.Number, i+1)
			if _, ok := out.Answers[key]; ok {
				out.JournalIssue = "duplicate_application_answer"
				markStep(&step, "not_possible", out.JournalIssue)
			}
			out.Answers[key] = recordedAnswer{Source: source, Context: ctx}
		}
		out.Steps = append(out.Steps, step)
		if row := status[n]; row != nil {
			if row.Steps == 0 {
				row.Status = "complete"
				row.Issues = []string{}
			}
			row.Steps++
			if rank(step.Completeness) > rank(row.Status) {
				row.Status = step.Completeness
			}
			for _, issue := range step.Issues {
				row.Issues = addIssue(row.Issues, issue)
			}
		}
	}
	for h := from; ; h++ {
		out.Heights = append(out.Heights, *status[strconv.FormatUint(h, 10)])
		if h == to {
			break
		}
	}
	return out, nil
}

func readChain(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return nil, errors.New("chain input must be regular and at most 256MiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, (256<<20)+1))
	if len(b) > 256<<20 {
		return nil, errors.New("chain input limit exceeded")
	}
	return b, err
}
func wireKey(run string, code uint64, payload []byte) string {
	h := sha256.Sum256(payload)
	return fmt.Sprintf("%s/%d/%x", run, code, h)
}
func rank(s string) int {
	switch s {
	case "complete":
		return 0
	case "partial":
		return 1
	default:
		return 2
	}
}
func markStep(s *Step, status, issue string) {
	if rank(status) > rank(s.Completeness) {
		s.Completeness = status
	}
	s.Issues = addIssue(s.Issues, issue)
}
func addIssue(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}
func safeInput(s string) string {
	switch s {
	case inputlog.KindStart, inputlog.KindStop, inputlog.KindNewHead, inputlog.KindRequest, inputlog.KindMessage, inputlog.KindCapturedMessage, inputlog.KindDeferredMessage, inputlog.KindBacklog, inputlog.KindTimeout, inputlog.KindCommitResult, inputlog.KindBroadcastFailed, inputlog.KindPeerConnected:
		return s
	default:
		return "unknown"
	}
}

func exactWireKey(run string, code uint64, payload []byte, mono time.Duration) string {
	return wireKey(run, code, payload) + "/" + strconv.FormatInt(int64(mono), 10)
}

func decodedMessage(s *Step, in consensus.Message) {
	sum := sha256.Sum256(in.Payload)
	s.PayloadSHA = hex.EncodeToString(sum[:])
	s.Peer = strings.ToLower(in.Peer.Hex())
	switch in.Code {
	case codec.CodePreprepare:
		s.Phase = "PRE-PREPARE"
	case codec.CodePrepare:
		s.Phase = "PREPARE"
	case codec.CodeCommit:
		s.Phase = "COMMIT"
	case codec.CodeRoundChange:
		s.Phase = "ROUND-CHANGE"
	}
	m, err := codec.DecodeMessage(in.Code, in.Payload)
	if err != nil {
		return
	}
	s.MessageHeight = m.View.Sequence.String()
	s.Round = m.View.Round.String()
	s.MessageDigest = strings.ToLower(m.Digest.Hex())
	if m.Proposal != nil && m.Proposal.Header != nil {
		s.MessageDigest = strings.ToLower(codec.BlockHash(m.Proposal.Header).Hex())
	}
}

func inspectCaptured(reader *journal.Reader, run string, record *journal.StepRec, step *Step) {
	ref, err := inputlog.CapturedReference(record.Input)
	if err != nil {
		markStep(step, "not_possible", "invalid_capture")
		return
	}
	step.Capture = strconv.FormatUint(ref, 10)
	frame, err := reader.ResolveCapture(run, ref)
	if err != nil {
		if errors.Is(err, journal.ErrCaptureMissing) {
			markStep(step, "partial", "missing_capture")
		} else {
			markStep(step, "not_possible", "invalid_capture")
		}
		return
	}
	payload, code, action, _ := transport.DecodeFrame(frame.Record.Code, frame.Record.Payload)
	if action != transport.FrameDeliver {
		markStep(step, "not_possible", "invalid_capture")
		return
	}
	in, err := inputlog.Decode(record.InputKind, record.Input, func(id uint64) ([]byte, error) {
		if id != ref {
			return nil, journal.ErrCapture
		}
		return payload, nil
	})
	if err != nil {
		markStep(step, "not_possible", "invalid_capture")
		return
	}
	message, ok := in.(consensus.Message)
	if !ok || uint64(message.Code) != code || message.Peer != frame.Peer {
		markStep(step, "not_possible", "invalid_capture")
		return
	}
	decodedMessage(step, message)
}
