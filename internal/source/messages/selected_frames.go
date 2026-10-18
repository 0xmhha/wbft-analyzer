package messages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
)

const MaxSelectedFrames = 100000
const MaxSelectedFrameBytes = 128 << 20

// SelectedFrame contains local execution bytes, never persisted metadata.
type SelectedFrame struct {
	Code    uint64 `json:"-"`
	Payload []byte `json:"-"`
}

// SelectedFramePayloads validates a bounded selection in one metadata pass.
// It preserves caller order and exposes no bytes until every exact source
// coordinate and the complete immutable fingerprint have been verified.
func SelectedFramePayloads(ctx context.Context, p Prepared, rows []Record, chain, genesis string) ([]SelectedFrame, error) {
	return selectedFramePayloads(ctx, p, rows, chain, genesis, MaxSelectedFrameBytes)
}

func selectedFramePayloads(ctx context.Context, p Prepared, rows []Record, chain, genesis string, maxBytes int) ([]SelectedFrame, error) {
	failure := errors.New("selected frame sources unavailable")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.Input.Kind != "frames" || len(rows) > MaxSelectedFrames || maxBytes < 0 || maxBytes > MaxSelectedFrameBytes {
		return nil, failure
	}
	type position struct {
		file string
		line int64
	}
	selected := make(map[position]int, len(rows))
	for i, row := range rows {
		key := position{row.File, row.Ordinal}
		if row.Type != "frame" || row.Dir != "in" || row.Decode != "decoded" || row.Signature != "recovered" || row.PeerStatus != "recorded" || row.Input != p.Summary.ID || row.Node != p.Summary.Node || row.Ordinal < 1 || !shaPattern.MatchString(row.PayloadSHA256) {
			return nil, failure
		}
		if _, duplicate := selected[key]; duplicate {
			return nil, failure
		}
		selected[key] = i
	}
	before, err := Fingerprint(ctx, p.Input)
	if err != nil || before.SHA256 != p.Summary.SHA256 {
		return nil, failure
	}
	matched := make([]bool, len(rows))
	_, err = Read(ctx, p, chain, genesis, func(actual Record) error {
		if i, found := selected[position{actual.File, actual.Ordinal}]; found {
			if matched[i] || !reflect.DeepEqual(actual, rows[i]) {
				return failure
			}
			matched[i] = true
		}
		return nil
	})
	if err != nil {
		return nil, failure
	}
	for _, found := range matched {
		if !found {
			return nil, failure
		}
	}
	root, err := os.OpenRoot(p.Input.Path)
	if err != nil {
		return nil, failure
	}
	defer root.Close()
	out := make([]SelectedFrame, 0, len(rows))
	remaining := maxBytes
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, err := root.Open("payloads/" + row.PayloadSHA256[:2] + "/" + row.PayloadSHA256)
		if err != nil {
			return nil, failure
		}
		limit := min(remaining, 16<<20)
		payload, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(payload) > limit {
			return nil, failure
		}
		remaining -= len(payload)
		hash := sha256.Sum256(payload)
		if hex.EncodeToString(hash[:]) != row.PayloadSHA256 {
			return nil, failure
		}
		var code uint64
		switch row.Phase {
		case "PRE-PREPARE":
			code = 0x12
		case "PREPARE":
			code = 0x13
		case "COMMIT":
			code = 0x14
		case "ROUND-CHANGE":
			code = 0x15
		default:
			return nil, failure
		}
		out = append(out, SelectedFrame{Code: code, Payload: payload})
	}
	after, err := Fingerprint(ctx, p.Input)
	if err != nil || after.SHA256 != before.SHA256 {
		return nil, failure
	}
	return out, nil
}
