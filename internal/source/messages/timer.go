package messages

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

func projectTimerOperation(b *journal.TimerRec) *TimerOperation {
	result := &TimerOperation{Sequence: number(b.Sequence), Action: b.Action, Source: b.Source, Output: number(b.Output), ArmEngine: number(b.ArmEngineRun), ArmStep: number(b.ArmStep), ArmOutput: number(b.ArmOutput), EntryMono: strconv.FormatInt(int64(b.EntryMono), 10), Deadline: strconv.FormatInt(int64(b.Deadline), 10), Kinds: []string{}, Decode: "not_applicable"}
	for _, kind := range b.Kinds {
		result.Kinds = append(result.Kinds, consensus.TimerKind(kind).String())
	}
	if len(b.Input) == 0 {
		return result
	}
	sum := sha256.Sum256(b.Input)
	result.TimeoutSHA256 = hex.EncodeToString(sum[:])
	result.Decode = "invalid"
	input, err := inputlog.Decode(inputlog.KindTimeout, b.Input, nil)
	if err != nil {
		return result
	}
	timer, ok := input.(consensus.Timeout)
	if !ok || timer.Kind > consensus.FutureTimer {
		return result
	}
	result.Decode = "complete"
	result.Timer = timer.Kind.String()
	result.Generation = number(timer.Gen)
	result.Height = timer.View.Sequence.String()
	result.Round = timer.View.Round.String()
	return result
}
