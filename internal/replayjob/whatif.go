package replayjob

import (
	"context"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
	"github.com/0xmhha/wbft-analyzer/internal/whatifjob"
)

type WhatifRequest struct {
	Source string        `json:"source_id"`
	Policy whatif.Policy `json:"timer_policy"`
}

func (w *Worker) SubmitWhatif(ctx context.Context, network, dataset int64, r WhatifRequest) (store.WhatifJob, error) {
	if !w.Available() {
		return store.WhatifJob{}, ErrSource
	}
	source, ok := w.sources[r.Source]
	if !ok || !source.info.AllowTimer || source.network != network || source.dataset != dataset {
		return store.WhatifJob{}, ErrSource
	}
	if r.Policy.Validate() != nil {
		return store.WhatifJob{}, ErrScope
	}
	job, err := w.store.EnqueueWhatif(ctx, store.WhatifJob{Dataset: dataset, Input: source.info.Input, Source: r.Source, SourceSHA: source.hash, InputSHA: source.inputSHA, ChainSHA: source.chainSHA, HelperSHA: source.helperSHA, Policy: r.Policy})
	if err == nil {
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
	return job, err
}
func (w *Worker) executeWhatif(ctx context.Context, job store.WhatifJob, owner string) error {
	status, issue := "failed", "source_unavailable"
	source, ok := w.sources[job.Source]
	if ok && source.info.AllowTimer && source.hash == job.SourceSHA && source.dataset == job.Dataset && source.info.Input == job.Input && source.inputSHA == job.InputSHA && source.chainSHA == job.ChainSHA && source.helperSHA == job.HelperSHA {
		chainSHA, e1 := fileSHA(source.chain)
		helperSHA, e2 := fileSHA(source.helper.Path)
		if e1 == nil && e2 == nil && chainSHA == source.chainSHA && helperSHA == source.helperSHA {
			helper := source.helper
			helper.ExpectedSHA = source.helperSHA
			work, cancel := context.WithTimeout(ctx, helper.Timeout)
			_, err := whatifjob.Run(work, w.store, whatifjob.Options{Dataset: job.Dataset, Input: job.Input, Chain: source.chain, Policy: job.Policy, Helper: &helper, ExpectedInputSHA: source.inputSHA, ExpectedNode: source.node, ExpectedChainSHA: source.chainSHA, JobID: job.ID, JobOwner: owner})
			cancel()
			if err == nil {
				status, issue = "succeeded", ""
			} else {
				issue = "experiment_failed"
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
	return w.store.FinishWhatifJob(cleanup, job.ID, owner, status, issue)
}
