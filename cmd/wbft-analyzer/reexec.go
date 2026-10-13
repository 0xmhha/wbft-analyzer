package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runReexecHelper(_ []string, stdout, stderr io.Writer) int {
	if err := reexec.Serve(context.Background(), os.Stdin, stdout); err != nil {
		fmt.Fprintln(stderr, "replay helper failed")
		return exitDataErr
	}
	return exitOK
}

func runReexec(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reexec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	dataset := fs.Int64("dataset", 0, "message dataset ID")
	input := fs.String("input", "", "retained journal input ID")
	chain := fs.String("chain", "", "recorded canonical chain.rlp")
	from := fs.Uint64("from", 0, "first active height (inclusive)")
	to := fs.Uint64("to", 0, "last active height (inclusive)")
	omit := fs.Bool("omit-missing-captures", false, "counterfactual: omit missing referenced received inputs")
	helper := fs.String("helper", "", "versioned wbft-replay executable; default: linked core in a child")
	timeout := fs.Duration("timeout", 5*time.Minute, "helper deadline, at most 30m")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *dsn == "" || *dataset < 1 || !logs.Identifier(*input) || *chain == "" || *from < 1 || *to < *from || *to-*from >= 10000 || *timeout <= 0 || *timeout > 30*time.Minute {
		fs.Usage()
		return exitUsage
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	s, err := store.Open(ctx, *dsn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUnavailable
	}
	defer s.Close()
	if _, err = s.Migrate(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return exitInternal
	}
	d, net, err := s.ReexecDataset(ctx, *dataset)
	if err != nil {
		fmt.Fprintln(stderr, "message dataset unavailable")
		return exitDataErr
	}
	inputs, err := s.MessageInputs(ctx, d.ID)
	if err != nil {
		return exitInternal
	}
	var summary messages.Summary
	for _, in := range inputs {
		if in.Summary.ID == *input {
			summary = in.Summary
		}
	}
	refs, err := s.InputFiles(ctx, d.ID, *input)
	if err != nil {
		return exitInternal
	}
	dir, err := reexec.Snapshot(ctx, summary, refs)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	defer os.RemoveAll(dir)
	chainObject, err := retainChain(ctx, *chain, filepath.Dir(refs[0].Path))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	// Helpers receive a verified private snapshot, not mutable object paths.
	chainFile := filepath.Join(dir, "chain.rlp")
	if err = reexec.CopyObject(ctx, chainObject, chainFile); err != nil {
		fmt.Fprintln(stderr, "recorded chain fingerprint mismatch")
		return exitDataErr
	}
	// The chain is kept beside, not inside, the fingerprinted journal directory.
	journalDir := filepath.Join(dir, "journal")
	if err = os.Mkdir(journalDir, 0700); err != nil {
		return exitInternal
	}
	for _, f := range summary.Files {
		if err = os.Rename(filepath.Join(dir, f.Name), filepath.Join(journalDir, f.Name)); err != nil {
			return exitInternal
		}
	}
	prepared := messages.Prepared{Input: messages.Input{ID: *input, Kind: "journal", Node: summary.Node, Path: journalDir}, Summary: summary}
	plan, err := reexec.Inspect(ctx, prepared, chainFile, net.ChainID, net.GenesisHash, *from, *to)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitDataErr
	}
	mode := "closed"
	if *omit {
		mode = "counterfactual"
	}
	initial := reexec.Result{Mode: mode, Version: reexec.Version, Status: "running", HelperVersion: "unknown", VersionStatus: "unknown", ChainSHA: plan.ChainSHA, SourceSHA: summary.SHA256, SourceVersions: plan.SourceVersions, Heights: plan.Heights}
	id, err := s.BeginReexec(ctx, d.ID, *input, strconv.FormatUint(*from, 10), strconv.FormatUint(*to, 10), chainObject.Path, initial)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitInternal
	}
	executable := *helper
	helperArgs := []string{}
	if executable == "" {
		executable, err = os.Executable()
		if err == nil {
			helperArgs = []string{"reexec-helper"}
		}
	}
	result := initial
	if err == nil {
		result, err = reexec.Execute(ctx, plan, reexec.Helper{Path: executable, Args: helperArgs, Timeout: *timeout, OmitMissing: *omit}, func(step reexec.Step) error { return s.PutReexecStep(ctx, id, step) })
	}
	if err != nil && result.Issue == "" {
		result.Status = "failed"
		result.Issue = "helper_failed"
	}
	cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	if e := s.FinishReexec(cleanup, id, result); e != nil {
		fmt.Fprintln(stderr, "cannot finish reexec run")
		return exitInternal
	}

	final, readErr := s.ReexecRun(cleanup, d.ID, id)
	if readErr != nil {
		return exitInternal
	}
	result = final.Summary
	if e := json.NewEncoder(stdout).Encode(struct {
		ID     int64         `json:"id"`
		Result reexec.Result `json:"result"`
	}{id, result}); e != nil {
		return exitInternal
	}
	if err != nil {
		fmt.Fprintln(stderr, "replay failed; see source completeness and helper status")
		return exitDataErr
	}
	return exitOK
}

func retainChain(ctx context.Context, path, directory string) (messages.ArchivedFile, error) {
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
