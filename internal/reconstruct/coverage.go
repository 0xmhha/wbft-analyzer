package reconstruct

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

type coverageKey struct{ run, peer, phase, sha string }
type coverageFrame struct {
	point Point
	at    time.Time
}
type frameCoverage map[coverageKey][]coverageFrame

func readFrameCoverage(ctx context.Context, m Manifest) (frameCoverage, error) {
	in := messages.Input{ID: "frames", Kind: "frames", Node: m.Node, Path: m.Frames.Path, SHA256: m.Frames.SHA256}
	prepared, _, err := messages.Prepare(ctx, messages.Manifest{Format: messages.Format, Name: "reconstruction", Network: m.Network, Clock: messages.Clock{Model: "unknown"}, Inputs: []messages.Input{in}})
	if err != nil {
		return nil, err
	}
	result := frameCoverage{}
	count := 0
	stats, err := messages.Read(ctx, prepared[0], m.Network.ChainID, m.Network.GenesisHash, func(row messages.Record) error {
		if row.Type != "frame" || row.Dir != "in" || row.PayloadSHA256 == "" || row.Peer == "" {
			return nil
		}
		count++
		if count > MaxProcessingRecords {
			return errors.New("reconstruction frame coverage exceeds 100000 records")
		}
		at, err := time.Parse(time.RFC3339Nano, row.Wall)
		if err != nil {
			return errors.New("reconstruction frame clock unavailable")
		}
		key := coverageKey{row.Run, row.Peer, row.Phase, row.PayloadSHA256}
		result[key] = append(result[key], coverageFrame{point: framePoint(row), at: at})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if stats.GapRecords != 0 || stats.SequenceGaps != 0 || stats.PartialRuns != 0 || stats.ClockRegressions != 0 {
		return nil, refusedBinding("frame_capture_incomplete")
	}
	final, err := messages.Fingerprint(ctx, in)
	if err != nil || final.SHA256 != prepared[0].Summary.SHA256 {
		return nil, errors.New("reconstruction frame source changed")
	}
	for key := range result {
		rows := result[key]
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].at.Before(rows[j].at) })
		result[key] = rows
	}
	return result, nil
}

func processingContent(source inputobs.Input, scope RunScope, node string, frames frameCoverage, log *executionLog) (*ProcessingCandidate, error) {
	if source.Kind != "message" {
		return nil, nil
	}
	at, err := time.Parse(time.RFC3339Nano, source.BeginWall)
	if err != nil {
		return nil, refusedBinding("processing_clock_unavailable")
	}
	content := &ProcessingCandidate{Peer: source.Peer, PayloadSHA256: source.PayloadSHA}
	if source.Peer == node {
		// Self delivery has no invented inbound frame. The directly observed
		// bytes are corroborated by an earlier signed own payload in this run.
		for _, row := range log.payloads[payloadKey{scope.LogRun, source.Code, source.PayloadSHA}] {
			if row.at.After(at) {
				break
			}
			p := row.payload
			if row.event.Run == scope.LogRun && p != nil && p.Status == "decoded" && p.Code == source.Code && p.Signer == node && p.SHA256 == source.PayloadSHA {
				content.Source, content.Digest = logPoint(row.event), p.Digest
				return content, nil
			}
		}
		return nil, refusedBinding("self_delivery_content_uncorroborated")
	}
	phase := map[string]string{"18": "PRE-PREPARE", "19": "PREPARE", "20": "COMMIT", "21": "ROUND-CHANGE"}[source.Code]
	rows := frames[coverageKey{scope.FrameRun, source.Peer, phase, source.PayloadSHA}]
	if len(rows) == 0 || rows[0].at.After(at) {
		return nil, refusedBinding("received_processing_content_uncorroborated")
	}
	// This is a content witness, not a claim that repeated equal frames can
	// be assigned a unique packet identity. Processing order and bytes come
	// from the separate closed observation boundary.
	content.Source = rows[0].point
	return content, nil
}
