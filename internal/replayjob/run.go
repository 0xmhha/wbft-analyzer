package replayjob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

var ErrStore = errors.New("replay storage failed")

type RunOptions struct {
	Dataset                                          int64
	Input                                            string
	Chain                                            string
	From, To                                         uint64
	Helper                                           reexec.Helper
	ExpectedInputSHA, ExpectedNode, ExpectedChainSHA string
}
type RunResult struct {
	ID     int64         `json:"id"`
	Result reexec.Result `json:"result"`
}

// Run snapshots retained inputs and uses the same core path for CLI and jobs.
func Run(ctx context.Context, s *store.Store, o RunOptions, onBegin func(int64) error) (RunResult, error) {
	var out RunResult
	if o.Dataset < 1 || !logs.Identifier(o.Input) || o.From < 1 || o.To < o.From || o.To-o.From >= 10000 || o.Helper.WarmupHeights > 10000 {
		return out, errors.New("invalid replay scope")
	}
	d, network, err := s.ReexecDataset(ctx, o.Dataset)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return out, err
		}
		return out, errors.Join(ErrStore, err)
	}
	inputs, err := s.MessageInputs(ctx, d.ID)
	if err != nil {
		return out, errors.Join(ErrStore, err)
	}
	var summary messages.Summary
	for _, input := range inputs {
		if input.Summary.ID == o.Input {
			summary = input.Summary
		}
	}
	if o.ExpectedInputSHA != "" && (summary.SHA256 != o.ExpectedInputSHA || summary.Node != o.ExpectedNode) {
		return out, ErrSource
	}
	refs, err := s.InputFiles(ctx, d.ID, o.Input)
	if err != nil {
		return out, errors.Join(ErrStore, err)
	}
	dir, err := reexec.Snapshot(ctx, summary, refs)
	if err != nil {
		return out, err
	}
	defer os.RemoveAll(dir)
	if len(refs) == 0 {
		return out, errors.New("retained input unavailable")
	}
	chain, err := RetainChain(ctx, o.Chain, filepath.Dir(refs[0].Path))
	if err != nil {
		return out, err
	}
	if o.ExpectedChainSHA != "" && chain.SHA256 != o.ExpectedChainSHA {
		return out, ErrSource
	}
	chainFile := filepath.Join(dir, "chain.rlp")
	if err = reexec.CopyObject(ctx, chain, chainFile); err != nil {
		return out, err
	}
	journalDir := filepath.Join(dir, "journal")
	if err = os.Mkdir(journalDir, 0700); err != nil {
		return out, err
	}
	for _, f := range summary.Files {
		if err = os.Rename(filepath.Join(dir, f.Name), filepath.Join(journalDir, f.Name)); err != nil {
			return out, err
		}
	}
	prepared := messages.Prepared{Input: messages.Input{ID: o.Input, Kind: "journal", Node: summary.Node, Path: journalDir}, Summary: summary}
	plan, err := reexec.Inspect(ctx, prepared, chainFile, network.ChainID, network.GenesisHash, o.From, o.To)
	if err != nil {
		return out, err
	}
	mode := "closed"
	if o.Helper.OmitMissing || o.Helper.AnswerScope == "context" {
		mode = "counterfactual"
	}
	initial := reexec.Result{OmitMissing: o.Helper.OmitMissing, AnswerScope: o.Helper.AnswerScope, WarmupHeights: int(o.Helper.WarmupHeights), Mode: mode, Version: reexec.Version, Status: "running", HelperVersion: "unknown", VersionStatus: "unknown", ChainSHA: plan.ChainSHA, SourceSHA: summary.SHA256, SourceVersions: plan.SourceVersions, Heights: plan.Heights}
	id, err := s.BeginReexec(ctx, d.ID, o.Input, strconv.FormatUint(o.From, 10), strconv.FormatUint(o.To, 10), chain.Path, initial)
	if err != nil {
		return out, errors.Join(ErrStore, err)
	}
	out.ID = id
	result := initial
	if onBegin != nil {
		err = onBegin(id)
	}
	if err == nil {
		result, err = reexec.Execute(ctx, plan, o.Helper, func(step reexec.Step) error {
			if err := s.PutReexecStep(ctx, id, step); err != nil {
				return errors.Join(ErrStore, err)
			}
			return nil
		})
	}
	if err != nil && result.Issue == "" {
		result.Status = "failed"
		result.Issue = "helper_failed"
	}
	cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	if finish := s.FinishReexec(cleanup, id, result); finish != nil {
		return out, errors.Join(ErrStore, finish)
	}
	final, readErr := s.ReexecRun(cleanup, d.ID, id)
	if readErr != nil {
		return out, errors.Join(ErrStore, readErr)
	}
	out.Result = final.Summary
	return out, err
}

func RetainChain(ctx context.Context, path, directory string) (messages.ArchivedFile, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return messages.ArchivedFile{}, errors.New("chain must be a regular file at most 256MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return messages.ArchivedFile{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1))
	if err != nil || n > 256<<20 {
		return messages.ArchivedFile{}, errors.New("chain size limit exceeded")
	}
	sum := hex.EncodeToString(h.Sum(nil))
	name := filepath.Base(path)
	p := messages.Prepared{Input: messages.Input{ID: "chain", Path: filepath.Dir(path)}, Summary: messages.Summary{Files: []messages.File{{Name: name, Bytes: n, SHA256: sum}}}}
	out, err := messages.Archive(ctx, directory, []messages.Prepared{p})
	if err != nil {
		return messages.ArchivedFile{}, err
	}
	return out["chain"][0], nil
}
