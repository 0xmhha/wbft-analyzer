// Package failuresources checks original scoped receive failure evidence.
// Cached failures remain separate from executed checks and accepted inputs.
package failuresources

import (
	"context"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/source/domainprofile"
	"io"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	"github.com/0xmhha/wbft/observe/journal"
)

const MaxLimitsBytes = 64 << 10

var ErrInput = errors.New("receive failure source input unavailable or invalid")

func Limits(raw []byte) (journal.ReceiveFailureLimits, error) {
	var limits journal.ReceiveFailureLimits
	if jsonmeta.Decode(raw, MaxLimitsBytes, true, &limits) != nil || !validLimits(limits) {
		return limits, ErrInput
	}
	return limits, nil
}

func validLimits(limits journal.ReceiveFailureLimits) bool {
	for _, n := range []uint64{limits.Caches, limits.Inbox.Operations, limits.Inbox.Entries, limits.Inbox.Peers, limits.Inbox.Frames, limits.Inbox.Bytes, limits.Inbox.Core.Records, limits.Inbox.Core.Runs, limits.Inbox.Core.Steps, limits.Inbox.Core.Environments, limits.Inbox.Core.Outputs, limits.Inbox.Core.Bytes} {
		if n == 0 {
			return false
		}
	}
	return true
}

// Check retains original records without converting hits into checks. Segment
// decoding precedes the record limit; byte budgets are checked after collection.
// These are finite inspection limits, not process memory bounds. A closed input
// must have the same fingerprint before and after loading and source checking.
func Check(ctx context.Context, directory string, limits journal.ReceiveFailureLimits) (journal.ReceiveFailureCheck, error) {
	if !validLimits(limits) {
		return journal.ReceiveFailureCheck{}, ErrInput
	}
	input := messages.Input{Kind: "journal", Path: directory}
	before, err := messages.Fingerprint(ctx, input)
	if err != nil {
		return journal.ReceiveFailureCheck{}, inputError(ctx)
	}
	reader, err := journal.OpenReader(nil, directory)
	if err != nil {
		return journal.ReceiveFailureCheck{}, ErrInput
	}
	var records []journal.Record
	var result journal.ReceiveFailureCheck
	var checkErr error
	for {
		if err := ctx.Err(); err != nil {
			return journal.ReceiveFailureCheck{}, err
		}
		record, err := reader.Next()
		if err == nil {
			err = domainprofile.Record(record)
		}
		if domainprofile.Unsupported(err) {
			return journal.ReceiveFailureCheck{Status: "unavailable", Reason: "unsupported_source_profile", PhysicalStatus: "unavailable", Scope: "original_failure_checks_bounded_cache_and_inbox_consumption", ScheduleStatus: "unavailable"}, nil
		}
		if errors.Is(err, io.EOF) {
			result, checkErr = journal.CheckReceiveFailureSources(records, limits)
			break
		}
		if err != nil {
			return journal.ReceiveFailureCheck{}, ErrInput
		}
		if uint64(len(records)) >= limits.Inbox.Core.Records {
			result = journal.ReceiveFailureCheck{Status: "unavailable", Reason: "record_limit", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable", Scope: "original_failure_checks_bounded_cache_and_inbox_consumption"}
			break
		}
		records = append(records, record)
	}
	after, err := messages.Fingerprint(ctx, input)
	if err != nil || before.SHA256 != after.SHA256 {
		return journal.ReceiveFailureCheck{}, inputError(ctx)
	}
	return result, checkErr
}

func inputError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrInput
}
