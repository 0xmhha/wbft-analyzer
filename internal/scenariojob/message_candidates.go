package scenariojob

import (
	"context"
	"math/big"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type MessagePosition struct {
	File    string
	Ordinal int64
}

func messageInSourceScope(row messages.Record, source registered) bool {
	height, ok := new(big.Int).SetString(row.Height, 10)
	wall, wallErr := time.Parse(time.RFC3339Nano, row.Wall)
	origin, originErr := time.Parse(time.RFC3339Nano, source.info.WallOrigin)
	return ok && height.IsUint64() && height.Uint64() >= source.request.Options.From && height.Uint64() <= source.request.Options.To && wallErr == nil && originErr == nil && !wall.Before(origin) && wall.Before(origin.Add(source.duration))
}

// MessageCandidates pages metadata within a registered transport input. These
// rows are candidates only: queueing rechecks exact objects and all signatures.
// Empty pages can have a next position when non-candidate frames were scanned.
func (w *Worker) MessageCandidates(ctx context.Context, network, dataset int64, id string, filter store.MessageFilter) ([]scenario.RecordedMessageEvidence, *MessagePosition, string, error) {
	source, ok := w.sources[id]
	if !ok || source.network != network || source.info.Dataset != dataset || source.info.Status != "complete" {
		return nil, nil, "", ErrSource
	}
	inputSHA := ""
	for _, input := range source.info.TransportInputs {
		if input.ID == filter.Input {
			inputSHA = input.SHA256
		}
	}
	if inputSHA == "" {
		return nil, nil, "", ErrChange
	}
	release, err := w.store.DatasetReadLease(ctx, dataset)
	if err != nil {
		return nil, nil, "", err
	}
	defer release()
	filter.Type, filter.Limit = "frame", 101
	rows, err := w.store.MessageRecords(ctx, dataset, filter)
	if err != nil {
		return nil, nil, "", err
	}
	var next *MessagePosition
	if len(rows) > 100 {
		rows = rows[:100]
		last := rows[len(rows)-1]
		next = &MessagePosition{File: last.File, Ordinal: last.Ordinal}
	}
	out := []scenario.RecordedMessageEvidence{}
	for _, row := range rows {
		if row.SigningProfile != nil {
			return nil, nil, "", ErrSource
		}
		if row.Dir != "in" || row.Decode != "decoded" || row.Signature != "recovered" || row.PeerStatus != "recorded" || !messageInSourceScope(row, source) {
			continue
		}
		out = append(out, scenario.RecordedMessageProjection(row, inputSHA))
	}
	return out, next, source.info.SourceSHA, nil
}
