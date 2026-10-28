// Package retrysources checks original current-view retry evidence without
// projecting it into legacy cache traces or treating queueing as delivery.
package retrysources

import (
	"context"
	"errors"
	"io"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	"github.com/0xmhha/wbft/observe/journal"
)

const MaxLimitsBytes = 64 << 10

var ErrInput = errors.New("retry source input unavailable or invalid")

func Limits(raw []byte) (journal.RetrySourceLimits, error) {
	var limits journal.RetrySourceLimits
	if jsonmeta.Decode(raw, MaxLimitsBytes, true, &limits) != nil || limits.Validate() != nil {
		return limits, ErrInput
	}
	return limits, nil
}

// Check decodes original segments before enforcing the explicit retained-input
// budgets. Those budgets are not process-heap or segment-allocation bounds.
// Missing observations remain unavailable; only the full core-owned source
// join can report conditional consistency. No functional runtime is executed.
func Check(ctx context.Context, directory string, limits journal.RetrySourceLimits) (journal.RetrySourceCheck, error) {
	if limits.Validate() != nil {
		return journal.RetrySourceCheck{}, ErrInput
	}
	reader, err := journal.OpenReader(nil, directory)
	if err != nil {
		return journal.RetrySourceCheck{}, ErrInput
	}
	var records []journal.Record
	var count uint64
	for {
		if err := ctx.Err(); err != nil {
			return journal.RetrySourceCheck{}, err
		}
		record, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return journal.CheckRoundChangeRetrySources(records, limits)
		}
		if err != nil {
			return journal.RetrySourceCheck{}, ErrInput
		}
		if count >= limits.Timers.Core.Records {
			return journal.RetrySourceCheck{Status: "unavailable", Reason: "record_limit", PhysicalStatus: "unavailable", Scope: "original_retry_owner_timer_signer_wal_cache_bindings"}, nil
		}
		count++
		switch record.Body.(type) {
		case *journal.SegmentRec, *journal.GapRec, *journal.CoreStepRec, *journal.TimerRec, *journal.SignerRec, *journal.SignerCallRec, *journal.WALReadRec, *journal.RestoreRec, *journal.CacheRec, *journal.WriteCacheRec:
			records = append(records, record)
		}
	}
}
