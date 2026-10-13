package reexec

import (
	"bufio"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/0xmhha/wbft/conformance/stepdriver"
)

var versionPattern = regexp.MustCompile(`^([0-9a-f]{40}|v[0-9]+\.[0-9]+\.[0-9]+(-[0-9]{14}-[0-9a-f]{12})?)$`)
var digestPattern = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
var ErrHelper = errors.New("replay helper protocol failed")

func safeVersion(s string) string {
	if len(s) <= 96 && versionPattern.MatchString(s) {
		return s
	}
	return "unknown"
}
func LinkedVersion() string {
	b, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, d := range b.Deps {
		if d.Path == "github.com/0xmhha/wbft" && d.Replace == nil {
			return safeVersion(d.Version)
		}
	}
	return "unknown"
}

type Helper struct {
	AnswerScope   string
	WarmupHeights uint64
	ExpectedSHA   string
	OmitMissing   bool
	Path          string
	Args          []string
	Timeout       time.Duration
}

type reply struct {
	AnswerScope      string               `json:"answer_scope"`
	ContextAnswers   bool                 `json:"context_answers"`
	AnswerSources    []helperAnswerSource `json:"answer_sources"`
	Features         []string             `json:"features"`
	Approximate      bool                 `json:"approximate"`
	Warmup           bool                 `json:"warmup"`
	ApproximateSteps int64                `json:"approximate_steps"`
	WarmupSteps      int64                `json:"warmup_steps"`
	Writer           string               `json:"writer_run"`
	Omitted          bool                 `json:"omitted"`
	Counterfactual   bool                 `json:"counterfactual"`
	Type             string               `json:"type"`
	ID               uint64               `json:"id"`
	Protocol         string               `json:"protocol"`
	Impl             string               `json:"impl"`
	Version          string               `json:"version"`
	Engine           uint64               `json:"engine_run"`
	Step             uint64               `json:"step"`
	Input            string               `json:"input"`
	Digest           string               `json:"out_digest"`
	Match            *bool                `json:"match"`
	Outputs          int64                `json:"outputs"`
	Steps            int64                `json:"steps"`
	Mismatches       int64                `json:"mismatches"`
	Code             string               `json:"code"`
}

// Execute bounds time, line size, total output and emitted steps. Only source
// coordinates, known classifications and digests cross the result boundary.
func Execute(ctx context.Context, p Plan, h Helper, yield func(Step) error) (res Result, err error) {
	scope := h.AnswerScope
	if scope == "" {
		scope = "step"
	}
	res = Result{OmitMissing: h.OmitMissing, AnswerScope: scope, WarmupHeights: int(h.WarmupHeights), Mode: "closed", Version: Version, Status: "failed", HelperVersion: "unknown", BinaryVersion: "unknown", VersionStatus: "unknown", ChainSHA: p.ChainSHA, SourceSHA: p.Input.Summary.SHA256, SourceVersions: p.SourceVersions, Heights: p.Heights}
	if h.OmitMissing || scope == "context" {
		res.Mode = "counterfactual"
	}
	if scope != "step" && scope != "context" {
		return res, ErrHelper
	}
	for _, s := range p.Steps {
		if hasIssue(s.Issues, "head_identity") {
			res.Issue = "head_identity"
			return res, ErrHelper
		}
	}
	if h.WarmupHeights > 10000 {
		return res, ErrHelper
	}
	if h.Timeout <= 0 || h.Timeout > 30*time.Minute {
		return res, errors.New("helper timeout must be positive and at most 30 minutes")
	}
	child, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	path, e := exec.LookPath(h.Path)
	if e != nil {
		return res, ErrHelper
	}
	path, e = filepath.Abs(path)
	if e != nil {
		return res, ErrHelper
	}
	if h.ExpectedSHA != "" {
		dir, err := os.MkdirTemp("", "wbft-replay-helper-")
		if err != nil {
			return res, ErrHelper
		}
		defer os.RemoveAll(dir)
		target := filepath.Join(dir, "helper")
		if err = snapshotHelper(child, path, target, h.ExpectedSHA); err != nil {
			return res, ErrHelper
		}
		path = target
	}
	res.BinaryVersion = binaryVersion(path)
	binaryHash, e := binarySHA(path)
	if e != nil {
		return res, ErrHelper
	}
	if h.ExpectedSHA != "" && h.ExpectedSHA != binaryHash {
		return res, ErrHelper
	}
	res.HelperSHA = binaryHash
	cmd := exec.CommandContext(child, path, h.Args...)
	cmd.WaitDelay = time.Second
	stdin, e := cmd.StdinPipe()
	if e != nil {
		return res, ErrHelper
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return res, ErrHelper
	}
	// Never retain arbitrary stderr, which may contain paths or input values.
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		return res, ErrHelper
	}
	waited := false
	defer func() {
		_ = stdin.Close()
		cancel()
		if !waited {
			_ = cmd.Wait()
		}
	}()
	scanner := bufio.NewScanner(io.LimitReader(stdout, 64<<20))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	next := func() (reply, error) {
		var r reply
		if !scanner.Scan() {
			return r, ErrHelper
		}
		if e := json.Unmarshal(scanner.Bytes(), &r); e != nil {
			return r, ErrHelper
		}
		return r, nil
	}
	encoder := json.NewEncoder(stdin)
	if e = encoder.Encode(map[string]any{"type": "hello", "protocol": Protocol}); e != nil {
		return res, ErrHelper
	}
	hello, e := next()
	if e != nil || hello.Type != "hello" || hello.Protocol != Protocol || hello.Impl != "wbft" {
		return res, ErrHelper
	}
	res.HelperVersion = safeVersion(hello.Version)
	if res.HelperVersion != "unknown" && sameVersion(res.BinaryVersion, res.HelperVersion) && len(p.SourceVersions) == 1 && sameVersion(p.SourceVersions[0], res.HelperVersion) {
		res.VersionStatus = "matched"
	} else if res.HelperVersion != "unknown" && sameVersion(res.BinaryVersion, res.HelperVersion) && len(p.SourceVersions) > 0 && p.SourceVersions[0] != "unknown" {
		res.VersionStatus = "different"
	}
	if scope == "context" && !hasIssue(hello.Features, "context_answers_v1") {
		res.Issue = "answer_scope_unsupported"
		return res, ErrHelper
	}
	execution := planExecution(p, h.WarmupHeights)
	if execution.bounded && !hasIssue(hello.Features, "bounded_warmup_v1") {
		res.Issue = "warmup_unsupported"
		return res, ErrHelper
	}
	request := map[string]any{"type": "replay", "id": uint64(1), "journal": p.Input.Input.Path, "chain": p.Chain, "from_step": 0, "to_step": 0, "with_vars": false, "omit_missing_captures": h.OmitMissing}
	if scope == "context" {
		request["answer_scope"] = "context"
	}
	if execution.bounded {
		request["warmup_from_height"] = execution.from
		request["compare_from_height"] = execution.compare
	}
	if e = encoder.Encode(request); e != nil {
		return res, ErrHelper
	}
	expected := execution.steps
	allComplete := true
	selected := map[string]Height{}
	for _, row := range p.Heights {
		selected[row.Number] = row
		if row.Status != "complete" {
			allComplete = false
		}
	}
	firstSelected := execution.firstSelected
	res.Warmup = &Warmup{Policy: "recorded_start", Status: "pending"}
	if firstSelected == 0 {
		res.Warmup.Status = "not_required"
	}
	if execution.bounded {
		res.Warmup.Policy = "bounded"
		res.Warmup.Status = "approximate"
		res.Warmup.FromHeight = strconv.FormatUint(execution.from, 10)
		res.Warmup.CompareFromHeight = strconv.FormatUint(execution.compare, 10)
	}
	index := 0
	var rawBad, rawApproximate, rawWarmup int64
	selectedApproximate := false
	usedAnswers := map[string]bool{}
	for {
		r, e := next()
		if e != nil {
			return res, ErrHelper
		}
		if r.ID != 1 {
			return res, ErrHelper
		}
		switch r.Type {
		case "error":
			res.Issue = "replay_error"
			if r.Code == "env_exhausted" {
				res.Issue = "env_exhausted"
			}
			if r.Code == "input_gap" {
				res.Issue = "input_gap"
			}
			if hasIssue([]string{"env_ambiguous", "env_source_mismatch", "head_mismatch", "answer_limit"}, r.Code) {
				res.Issue = r.Code
			}
			if r.Code == "warmup_unavailable" {
				res.Issue = "warmup_unavailable"
				res.Warmup.Status = "failed"
			}
			if r.Writer != "" {
				if index >= len(expected) {
					return res, ErrHelper
				}
				s := expected[index]
				if r.Writer != s.Run || strconv.FormatUint(r.Engine, 10) != s.Engine || strconv.FormatUint(r.Step, 10) != s.Number {
					return res, ErrHelper
				}
				if r.Code != "warmup_unavailable" && r.Approximate != s.Approximate {
					return res, ErrHelper
				}
				s.Approximate = r.Approximate
				if index < firstSelected {
					s.Class = "not_comparable"
					if r.Code == "env_exhausted" || r.Code == "input_gap" {
						s.Class = r.Code
						if s.Approximate && r.Code == "env_exhausted" {
							s.Class = "warmup_suspect"
						}
					}
					s.Issues = addIssue(s.Issues, res.Issue)
					recordWarmup(res.Warmup, s)
					res.Warmup.Status = "failed"
				}
				if _, included := selected[s.Height]; included {
					s.Class = "not_comparable"
					if r.Code == "env_exhausted" || r.Code == "input_gap" {
						s.Class = r.Code
						if s.Approximate && r.Code == "env_exhausted" {
							s.Class = "warmup_suspect"
						}
					}
					s.Issues = addIssue(s.Issues, res.Issue)
					res.Total++
					if s.Class == "warmup_suspect" {
						res.WarmupSuspect++
					} else if r.Code == "env_exhausted" {
						res.Mismatches++
						if res.FirstMismatch == nil {
							n := s.Ordinal
							res.FirstMismatch = &n
						}
					} else {
						res.NotComparable++
					}
					if e = yield(s); e != nil {
						return res, e
					}
				}
			}
			return res, ErrHelper
		case "step":
			if index >= len(expected) || index >= MaxSteps || r.Match == nil || !digestPattern.MatchString(r.Digest) || r.Outputs < 0 || r.Outputs > 1000000 {
				return res, ErrHelper
			}
			s := expected[index]
			if (execution.unavailable && execution.unavailableAt == s.Ordinal) || r.Approximate != s.Approximate || r.Warmup != s.Warmup {
				return res, ErrHelper
			}
			if r.Approximate {
				rawApproximate++
			}
			if r.Warmup {
				rawWarmup++
			}
			index++
			if r.Writer != "" && r.Writer != s.Run || strconv.FormatUint(r.Engine, 10) != s.Engine || strconv.FormatUint(r.Step, 10) != s.Number || r.Input != s.Input {
				return res, ErrHelper
			}
			if !*r.Match {
				rawBad++
			}
			if *r.Match && r.Digest != s.Recorded {
				return res, ErrHelper
			}
			s.ContextAnswers = r.ContextAnswers
			if r.ContextAnswers != (scope == "context") {
				return res, ErrHelper
			}
			sources, e := verifiedAnswerSources(p, s, r.AnswerSources, usedAnswers)
			if e != nil || (scope != "context" && len(sources) != 0) {
				return res, ErrHelper
			}
			s.AnswerSources = sources
			s.Omitted = r.Omitted
			if r.Omitted != (h.OmitMissing && s.Capture != "" && onlyMissingCapture(s.Issues)) {
				return res, ErrHelper
			}
			row, included := selected[s.Height]
			if !included {
				if index <= firstSelected || execution.bounded && s.Warmup {
					s = classifyStep(s, r, s.Completeness == "complete" || approximateComparable(s))
					recordWarmup(res.Warmup, s)
				}
				continue
			}
			res.Total++
			s = classifyStep(s, r, comparableStep(s, row, h.OmitMissing) || approximateComparable(s) || execution.bounded && restoredComparable(s, row))
			if s.Approximate {
				selectedApproximate = true
			}
			switch s.Class {
			case "match":
				res.Matches++
			case "warmup_suspect":
				res.WarmupSuspect++
			case "output_diverged", "env_mismatch":
				res.Mismatches++
				if res.FirstMismatch == nil {
					n := s.Ordinal
					res.FirstMismatch = &n
				}
			default:
				res.NotComparable++
			}
			if e = yield(s); e != nil {
				return res, e
			}
		case "done":
			if (h.OmitMissing || scope == "context") != r.Counterfactual || scope == "context" && r.AnswerScope != "context" || scope == "step" && r.AnswerScope != "" && r.AnswerScope != "step" {
				return res, ErrHelper
			}
			if execution.bounded && (r.ApproximateSteps != rawApproximate || r.WarmupSteps != rawWarmup) {
				return res, ErrHelper
			}
			if r.Steps != int64(index) || index != len(expected) || r.Mismatches != rawBad {
				return res, ErrHelper
			}
			if e = encoder.Encode(map[string]any{"type": "bye"}); e != nil {
				return res, ErrHelper
			}
			_ = stdin.Close()
			if scanner.Scan() || scanner.Err() != nil {
				return res, ErrHelper
			}
			e = cmd.Wait()
			waited = true
			if e != nil {
				return res, ErrHelper
			}

			source, e := messages.Fingerprint(ctx, p.Input.Input)
			if e != nil || source.SHA256 != p.Input.Summary.SHA256 {
				res.Issue = "input_changed"
				return res, ErrHelper
			}
			chain, e := readChain(p.Chain)
			if e != nil {
				return res, ErrHelper
			}
			chainHash := sha256.Sum256(chain)
			finalBinary, e := binarySHA(path)
			if hex.EncodeToString(chainHash[:]) != p.ChainSHA || e != nil || finalBinary != binaryHash {
				res.Issue = "input_changed"
				return res, ErrHelper
			}
			if execution.bounded {
				res.Warmup.Status = "approximate"
			} else {
				finishWarmup(res.Warmup)
			}
			if res.Total == 0 {
				res.Status = "not_possible"
				res.Issue = "no_replayed_steps"
			} else if h.OmitMissing || scope == "context" {
				res.Status = "counterfactual"
			} else if selectedApproximate {
				res.Status = "partial"
				res.Issue = "approximate_state"
			} else if res.Warmup.Status == "partial" {
				res.Status = "partial"
				res.Issue = "warmup_incomplete"
			} else if res.Warmup.Status == "diverged" {
				res.Status = "diverged"
				res.Issue = "warmup_diverged"
			} else if res.NotComparable > 0 || !allComplete {
				res.Status = "partial"
			} else if res.VersionStatus != "matched" {
				res.Status = "regression"
			} else if res.Mismatches > 0 {
				res.Status = "diverged"
			} else {
				res.Status = "reproduced"
			}
			return res, nil
		default:
			return res, ErrHelper
		}
	}
}

// Serve runs the existing WBFT core in a bounded child. It adds no consensus
// transition, scheduling, validation or signing implementation.
func Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 4096), 64<<10)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var r struct {
			Schedule    *stepdriver.TraceSchedule `json:"input_schedule"`
			AnswerScope string                    `json:"answer_scope"`
			Type        string                    `json:"type"`
			Protocol    string                    `json:"protocol"`
			ID          uint64                    `json:"id"`
			Journal     string                    `json:"journal"`
			Chain       string                    `json:"chain"`
			OmitMissing bool                      `json:"omit_missing_captures"`
			WarmupFrom  uint64                    `json:"warmup_from_height"`
			CompareFrom uint64                    `json:"compare_from_height"`
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return ErrHelper
		}
		switch r.Type {
		case "hello":
			if r.Protocol != Protocol {
				return ErrHelper
			}
			if err := enc.Encode(map[string]any{"type": "hello", "protocol": Protocol, "impl": "wbft", "version": LinkedVersion(), "features": []string{"bounded_warmup_v1", "context_answers_v1", "input_schedule_v1"}}); err != nil {
				return err
			}
		case "bye":
			return nil
		case "replay":
			if err := serveReplay(ctx, r.Journal, r.Chain, r.ID, r.OmitMissing, r.WarmupFrom, r.CompareFrom, r.AnswerScope, r.Schedule, enc); err != nil {
				return err
			}
		default:
			return ErrHelper
		}
	}
	return sc.Err()
}

func digest(h [32]byte) string { return "0x" + hex.EncodeToString(h[:]) }

func binaryVersion(path string) string {
	b, err := buildinfo.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	for _, d := range b.Deps {
		if d.Path == "github.com/0xmhha/wbft" && d.Replace == nil {
			return safeVersion(d.Version)
		}
	}
	if b.Main.Path != "github.com/0xmhha/wbft" {
		return "unknown"
	}
	var revision, modified string
	for _, s := range b.Settings {
		if s.Key == "vcs.revision" {
			revision = s.Value
		}
		if s.Key == "vcs.modified" {
			modified = s.Value
		}
	}
	if revision != "" {
		if modified == "false" {
			return safeVersion(revision)
		}
		return "unknown"
	}
	return safeVersion(b.Main.Version)
}
func binarySHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return "", ErrHelper
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, (256<<20)+1))
	if err != nil || n > 256<<20 {
		return "", ErrHelper
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func onlyMissingCapture(issues []string) bool {
	if len(issues) == 0 {
		return false
	}
	for _, issue := range issues {
		if issue != "missing_capture" {
			return false
		}
	}
	return true
}
func comparableStep(s Step, h Height, omit bool) bool {
	if s.Completeness == "complete" && h.Status == "complete" {
		return true
	}
	if !omit || h.Status == "not_possible" || !onlyMissingCapture(h.Issues) {
		return false
	}
	return s.Completeness == "complete" || s.Completeness == "partial" && onlyMissingCapture(s.Issues)
}

// snapshotHelper pins the operator-approved executable before starting it.
func snapshotHelper(ctx context.Context, source, target, expected string) error {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return ErrHelper
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	defer out.Close()
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var total int64
	reader := io.LimitReader(in, info.Size()+1)
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		n, e := reader.Read(buf)
		if n > 0 {
			if _, err = out.Write(buf[:n]); err != nil {
				return err
			}
			_, _ = h.Write(buf[:n])
			total += int64(n)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
	}
	if total != info.Size() || hex.EncodeToString(h.Sum(nil)) != expected {
		return ErrHelper
	}
	return out.Sync()
}
