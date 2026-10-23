package scenario

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/journal"
)

func receiveLimits(profile *messages.ReceiveProfile, replay bool) (*runner.NextHeightLimits, error) {
	if profile == nil {
		return nil, nil
	}
	if profile.Version != "1" || !replay {
		return nil, errors.New("unsupported receive profile or WAL replay unavailable")
	}
	values := make([]uint64, 4)
	for i, raw := range []string{profile.Entries, profile.Bytes, profile.PerPeer, profile.PerSource} {
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != raw {
			return nil, errors.New("invalid exact receive limits")
		}
		values[i] = value
	}
	return &runner.NextHeightLimits{Entries: values[0], Bytes: values[1], PerPeer: values[2], PerSource: values[3]}, nil
}

func selectedStepCapture(writer string, step *journal.StepRec) (string, uint64, bool, error) {
	switch step.InputKind {
	case inputlog.KindCapturedMessage:
		capture, err := inputlog.CapturedReference(step.Input)
		return writer, capture, false, err
	case inputlog.KindDeferredMessage:
		_, origin, err := inputlog.DecodeDeferredMessage(step.Input)
		return origin.Run, origin.Capture, true, err
	default:
		return "", 0, false, nil
	}
}
func verifyDeferredSelection(reader journal.CaptureResolver, body []byte, expectedHash string) error {
	m, e, err := journal.InspectDeferred(reader, body)
	if err != nil || e.Status != "verified" {
		return errors.New("selected deferred origin unavailable")
	}
	sum := sha256.Sum256(m.Payload)
	if hex.EncodeToString(sum[:]) != expectedHash {
		return errors.New("selected deferred payload identity mismatch")
	}
	return nil
}
