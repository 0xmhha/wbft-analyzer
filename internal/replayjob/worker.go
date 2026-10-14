package replayjob

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

var ErrSource = errors.New("replay source unavailable")
var ErrScope = errors.New("invalid replay scope")

type SourceSpec struct {
	AllowSchedule bool   `json:"allow_schedule,omitempty"`
	AllowContext  bool   `json:"allow_context,omitempty"`
	ID            string `json:"id"`
	Dataset       int64  `json:"dataset"`
	Input         string `json:"input"`
	Chain         string `json:"chain"`
	Helper        string `json:"helper,omitempty"`
	Timeout       string `json:"timeout,omitempty"`
	AllowLoss     bool   `json:"allow_loss,omitempty"`
}
type SourceInfo struct {
	AllowSchedule bool     `json:"allow_schedule"`
	AnswerScopes  []string `json:"answer_scopes"`
	ID            string   `json:"id"`
	Input         string   `json:"input_id"`
	Modes         []string `json:"modes"`
}
type source struct {
	info                        SourceInfo
	network, dataset            int64
	chain, hash, inputSHA, node string
	chainSHA, helperSHA         string
	helper                      reexec.Helper
}
type Request struct {
	Schedule      *reexec.InputSchedule `json:"input_schedule,omitempty"`
	AnswerScope   string                `json:"answer_scope,omitempty" enum:"step,context"`
	WarmupHeights *int                  `json:"warmup_heights,omitempty"`
	Source        string                `json:"source_id"`
	From          string                `json:"from_height"`
	To            string                `json:"to_height"`
	Mode          string                `json:"mode" enum:"closed,counterfactual"`
}
type Worker struct {
	store   *store.Store
	sources map[string]source
	order   []string
	wake    chan struct{}
	running atomic.Bool
}

func Load(ctx context.Context, s *store.Store, path, linked string) (*Worker, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 || info.Mode().Perm()&0077 != 0 {
		return nil, ErrSource
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrSource
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	_ = f.Close()
	if err != nil || len(raw) > 64<<10 {
		return nil, ErrSource
	}
	var specs []SourceSpec
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&specs) != nil || decoder.Decode(new(any)) != io.EOF || len(specs) < 1 || len(specs) > 16 {
		return nil, ErrSource
	}
	worker := &Worker{store: s, sources: map[string]source{}, wake: make(chan struct{}, 1)}
	for _, spec := range specs {
		if !logs.Identifier(spec.ID) || !logs.Identifier(spec.Input) || spec.Dataset < 1 || spec.Chain == "" {
			return nil, ErrSource
		}
		if spec.AllowSchedule && !spec.AllowContext {
			return nil, ErrSource
		}
		if _, ok := worker.sources[spec.ID]; ok {
			return nil, ErrSource
		}
		dataset, _, err := s.ReexecDataset(ctx, spec.Dataset)
		if err != nil {
			return nil, ErrSource
		}
		inputs, err := s.MessageInputs(ctx, spec.Dataset)
		if err != nil {
			return nil, err
		}
		inputSHA, node := "", ""
		for _, in := range inputs {
			if in.Summary.ID == spec.Input && in.Summary.Kind == "journal" {
				inputSHA, node = in.Summary.SHA256, in.Summary.Node
			}
		}
		refs, err := s.InputFiles(ctx, spec.Dataset, spec.Input)
		if err != nil || len(refs) == 0 || inputSHA == "" {
			return nil, ErrSource
		}
		chainPath := spec.Chain
		if !filepath.IsAbs(chainPath) {
			chainPath = filepath.Join(filepath.Dir(path), chainPath)
		}
		storage, storageErr := s.InputStorageDirectory(ctx, spec.Dataset)
		if errors.Is(storageErr, store.ErrNotFound) {
			storage = filepath.Dir(refs[0].Path)
		} else if storageErr != nil {
			return nil, ErrSource
		}
		release, leaseErr := s.DatasetReadLease(ctx, spec.Dataset)
		if leaseErr != nil {
			return nil, ErrSource
		}
		chain, err := RetainChain(ctx, chainPath, storage)
		release()
		if err != nil {
			return nil, ErrSource
		}
		helper := reexec.Helper{Path: linked, Args: []string{"reexec-helper"}, Timeout: 5 * time.Minute}
		if spec.Helper != "" {
			helper.Path = spec.Helper
			helper.Args = nil
			if !filepath.IsAbs(helper.Path) {
				helper.Path = filepath.Join(filepath.Dir(path), helper.Path)
			}
		}
		if spec.Timeout != "" {
			helper.Timeout, err = time.ParseDuration(spec.Timeout)
			if err != nil || helper.Timeout <= 0 || helper.Timeout > 30*time.Minute {
				return nil, ErrSource
			}
		}
		helperSHA, err := fileSHA(helper.Path)
		if err != nil {
			return nil, ErrSource
		}
		modes := []string{"closed"}
		if spec.AllowLoss {
			modes = append(modes, "counterfactual")
		}
		scopes := []string{"step"}
		if spec.AllowContext {
			scopes = append(scopes, "context")
		}
		identity, _ := json.Marshal(struct {
			Dataset                                             int64
			Input, InputSHA, Node, ChainSHA, HelperSHA, Timeout string
			Modes, AnswerScopes                                 []string
			AllowSchedule                                       bool
		}{spec.Dataset, spec.Input, inputSHA, node, chain.SHA256, helperSHA, helper.Timeout.String(), modes, scopes, spec.AllowSchedule})
		hash := sha256.Sum256(identity)
		worker.sources[spec.ID] = source{info: SourceInfo{AllowSchedule: spec.AllowSchedule, ID: spec.ID, Input: spec.Input, Modes: modes, AnswerScopes: scopes}, network: dataset.NetworkID, dataset: spec.Dataset, chain: chain.Path, hash: hex.EncodeToString(hash[:]), inputSHA: inputSHA, node: node, helper: helper, chainSHA: chain.SHA256, helperSHA: helperSHA}
		worker.order = append(worker.order, spec.ID)
	}
	return worker, nil
}
func fileSHA(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return "", ErrSource
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1)); err != nil || n != info.Size() {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (w *Worker) Sources(network, dataset int64) []SourceInfo {
	out := []SourceInfo{}
	for _, id := range w.order {
		s := w.sources[id]
		if s.network == network && s.dataset == dataset {
			out = append(out, s.info)
		}
	}
	return out
}
func (w *Worker) Submit(ctx context.Context, network, dataset int64, r Request) (store.ReexecJob, error) {
	if !w.running.Load() {
		return store.ReexecJob{}, ErrSource
	}
	source, ok := w.sources[r.Source]
	if !ok || source.network != network || source.dataset != dataset {
		return store.ReexecJob{}, ErrSource
	}
	from, e1 := strconv.ParseUint(r.From, 10, 64)
	to, e2 := strconv.ParseUint(r.To, 10, 64)
	if e1 != nil || e2 != nil || strconv.FormatUint(from, 10) != r.From || strconv.FormatUint(to, 10) != r.To || from < 1 || to < from || to-from >= 10000 {
		return store.ReexecJob{}, ErrScope
	}
	scope := r.AnswerScope
	if scope == "" {
		scope = "step"
	}
	if scope != "step" && scope != "context" {
		return store.ReexecJob{}, ErrScope
	}
	if scope == "context" && !hasScope(source.info.AnswerScopes, scope) {
		return store.ReexecJob{}, ErrScope
	}
	warmup := 2
	if r.WarmupHeights != nil {
		warmup = *r.WarmupHeights
	}
	if warmup < 0 || warmup > 10000 {
		return store.ReexecJob{}, ErrScope
	}
	allowed := false
	for _, mode := range source.info.Modes {
		if r.Mode == mode {
			allowed = true
		}
	}
	if !allowed {
		return store.ReexecJob{}, ErrScope
	}
	if r.Schedule != nil && (!source.info.AllowSchedule || scope != "context" || warmup != 0 || r.Mode != "closed") {
		return store.ReexecJob{}, ErrScope
	}
	job, err := w.store.EnqueueReexec(ctx, store.ReexecJob{Dataset: dataset, Input: source.info.Input, Source: r.Source, SourceSHA: source.hash, From: r.From, To: r.To, Mode: r.Mode, WarmupHeights: warmup, AnswerScope: scope, Schedule: r.Schedule})
	if err == nil {
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
	return job, err
}

// Start owns one database/schema worker and fails rather than splitting ownership.
func (w *Worker) Start(ctx context.Context) (func(), error) {
	lease, err := w.store.ReexecWorkerLease(ctx)
	if err != nil {
		return nil, err
	}
	if err = w.store.RecoverReexecJobs(ctx); err != nil {
		_ = lease.Close(context.Background())
		return nil, err
	}
	var token [16]byte
	if _, err = rand.Read(token[:]); err != nil {
		_ = lease.Close(context.Background())
		return nil, err
	}
	owner := hex.EncodeToString(token[:])
	work, cancel := context.WithCancel(ctx)
	w.running.Store(true)
	done := make(chan struct{})
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-work.Done():
				return
			case <-ticker.C:
				ping, stop := context.WithTimeout(work, 2*time.Second)
				err := lease.Ping(ping)
				stop()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	go func() {
		defer close(done)
		defer w.running.Store(false)
		defer cancel()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if work.Err() != nil {
				return
			}
			job, err := w.store.ClaimReexecJob(work, owner)
			if errors.Is(err, store.ErrNotFound) {
				select {
				case <-work.Done():
					return
				case <-ticker.C:
				case <-w.wake:
				}
				continue
			}
			if err != nil {
				return
			}
			if w.execute(work, job, owner) != nil {
				return
			}
		}
	}()
	return func() { cancel(); <-done; <-heartbeatDone; _ = lease.Close(context.Background()) }, nil
}
func (w *Worker) execute(ctx context.Context, job store.ReexecJob, owner string) error {
	status, issue := "failed", "source_unavailable"
	source, ok := w.sources[job.Source]
	if ok && source.hash == job.SourceSHA && source.dataset == job.Dataset && source.info.Input == job.Input {
		inputs, err := w.store.MessageInputs(ctx, job.Dataset)
		same := false
		if err == nil {
			for _, input := range inputs {
				if input.Summary.ID == job.Input && input.Summary.SHA256 == source.inputSHA && input.Summary.Node == source.node {
					same = true
				}
			}
		}
		if same {
			chainSHA, e1 := fileSHA(source.chain)
			helperSHA, e2 := fileSHA(source.helper.Path)
			same = e1 == nil && e2 == nil && chainSHA == source.chainSHA && helperSHA == source.helperSHA
		}
		if same {
			from, _ := strconv.ParseUint(job.From, 10, 64)
			to, _ := strconv.ParseUint(job.To, 10, 64)
			helper := source.helper
			helper.ExpectedSHA = source.helperSHA
			helper.OmitMissing = job.Mode == "counterfactual"
			helper.WarmupHeights = uint64(job.WarmupHeights)
			helper.AnswerScope = job.AnswerScope
			helper.Schedule = job.Schedule
			_, err = Run(ctx, w.store, RunOptions{Dataset: job.Dataset, Input: job.Input, Chain: source.chain, From: from, To: to, Helper: helper, ExpectedInputSHA: source.inputSHA, ExpectedNode: source.node, ExpectedChainSHA: source.chainSHA}, func(id int64) error { return w.store.LinkReexecJob(ctx, job.ID, owner, id) })
			if err == nil {
				status, issue = "succeeded", ""
			} else {
				issue = "replay_failed"
			}
		} else {
			issue = "source_changed"
		}
	}
	if ctx.Err() != nil {
		status, issue = "cancelled", "worker_stopped"
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return w.store.FinishReexecJob(cleanup, job.ID, owner, status, issue)
}

func (w *Worker) Available() bool { return w.running.Load() }

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
