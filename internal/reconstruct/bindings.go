package reconstruct

import (
	"bytes"
	"strconv"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/ethereum/go-ethereum/common"
)

type boundInput struct {
	in     consensus.Input
	future *consensus.Timeout
	via    string
	arm    *Point
}

type timerBinding struct {
	arm            consensus.ArmTimer
	source         Point
	observed       Projection
	earliest, last time.Time
	live           bool
}

// inputBindings retains only outputs of this reconstructed engine. It never
// makes an arbitrary payload trusted by recovering it as a backlog replay.
type inputBindings struct {
	replays []*consensus.Verified
	timers  []timerBinding
}

func refusedBinding(reason string) error { return envFailure{Reason: reason} }

func inputPayload(source inputobs.Input) error {
	if source.PayloadAvailable == nil || !*source.PayloadAvailable || sourceSHA(source.Payload) != source.PayloadSHA {
		return refusedBinding("processing_payload_unavailable")
	}
	return nil
}

func replayMatches(v *consensus.Verified, source inputobs.Input, code codec.Code) bool {
	if v == nil || v.Msg == nil || v.Msg.Code != code {
		return false
	}
	raw, err := v.Encode()
	return err == nil && bytes.Equal(raw, source.Payload)
}

func (b *inputBindings) bind(source inputobs.Input) (boundInput, error) {
	plain := func(in consensus.Input) (boundInput, error) {
		return boundInput{in: in, via: "observed_processing_boundary"}, nil
	}
	switch source.Kind {
	case "start":
		return plain(consensus.Start{})
	case "stop":
		return plain(consensus.Stop{})
	case "head":
		// Head bytes and identity are supplied only through the recorded Head
		// answer. The header carried in NewHead is not read by State.Step.
		return plain(consensus.NewHead{})
	case "request":
		if source.NilRequest {
			return plain(consensus.Request{})
		}
		if err := inputPayload(source); err != nil {
			return boundInput{}, err
		}
		block, err := codec.DecodeBlock(source.Payload)
		if err != nil {
			return boundInput{}, refusedBinding("proposal_request_encoding_unavailable")
		}
		return plain(consensus.Request{Block: block})
	case "message", "backlog":
		if err := inputPayload(source); err != nil {
			return boundInput{}, err
		}
		code, err := strconv.ParseUint(source.Code, 10, 64)
		if err != nil || strconv.FormatUint(code, 10) != source.Code {
			return boundInput{}, refusedBinding("processing_message_code_unavailable")
		}
		if source.Kind == "backlog" {
			return b.backlog(source, codec.Code(code))
		}
		if source.PeerKnown == nil || !*source.PeerKnown || !addressPattern.MatchString(source.Peer) {
			return boundInput{}, refusedBinding("processing_peer_unavailable")
		}
		mono, err := strconv.ParseInt(source.BeginMono, 10, 64)
		if err != nil || mono < 0 {
			return boundInput{}, refusedBinding("processing_clock_unavailable")
		}
		return plain(consensus.Message{Code: codec.Code(code), Payload: source.Payload, Peer: common.HexToAddress(source.Peer), RecvMono: time.Duration(mono)})
	case "round_timeout", "retry_timeout":
		kind := consensus.RoundTimer
		if source.Kind == "retry_timeout" {
			kind = consensus.RetryTimer
		}
		at, err := time.Parse(time.RFC3339Nano, source.BeginWall)
		if err != nil {
			return boundInput{}, refusedBinding("processing_clock_unavailable")
		}
		index := -1
		definite := false
		for i, timer := range b.timers {
			if timer.arm.Kind != kind || at.Before(timer.earliest.Add(timer.arm.Duration)) || kind == consensus.RetryTimer && timer.arm.Round.String() != source.TargetRound {
				continue
			}
			if index != -1 {
				return boundInput{}, refusedBinding("timer_source_binding_ambiguous")
			}
			index = i
			definite = !at.Before(timer.last.Add(timer.arm.Duration))
		}
		if index < 0 || !definite {
			return boundInput{}, refusedBinding("timer_source_binding_unavailable")
		}
		timer := b.timers[index]
		b.timers = append(b.timers[:index], b.timers[index+1:]...)
		return boundInput{in: consensus.Timeout{Kind: kind, View: timer.arm.View, Round: timer.arm.Round, Gen: timer.arm.Gen}, via: "derived_timer_generation", arm: &timer.source}, nil
	default:
		return boundInput{}, refusedBinding("processing_input_kind_unavailable")
	}
}

func (b *inputBindings) backlog(source inputobs.Input, code codec.Code) (boundInput, error) {
	replay, future := -1, -1
	count := 0
	for i, candidate := range b.replays {
		if replayMatches(candidate, source, code) {
			replay, count = i, count+1
		}
	}
	at, err := time.Parse(time.RFC3339Nano, source.BeginWall)
	if err != nil {
		return boundInput{}, refusedBinding("processing_clock_unavailable")
	}
	for i, timer := range b.timers {
		if timer.arm.Kind == consensus.FutureTimer && !at.Before(timer.earliest.Add(timer.arm.Duration)) && replayMatches(timer.arm.Msg, source, code) {
			future, count = i, count+1
		}
	}
	if count > 1 {
		return boundInput{}, refusedBinding("backlog_source_binding_ambiguous")
	}
	if count == 0 {
		return boundInput{}, refusedBinding("backlog_source_binding_unavailable")
	}
	if replay >= 0 {
		candidate := b.replays[replay]
		b.replays = append(b.replays[:replay], b.replays[replay+1:]...)
		return boundInput{in: consensus.Replay{Msg: candidate}, via: "unique_recorded_schedule"}, nil
	}
	timer := b.timers[future]
	if at.Before(timer.last.Add(timer.arm.Duration)) {
		return boundInput{}, refusedBinding("timer_source_binding_unavailable")
	}
	b.timers = append(b.timers[:future], b.timers[future+1:]...)
	expiry := consensus.Timeout{Kind: consensus.FutureTimer, View: timer.arm.View, Round: timer.arm.Round, Gen: timer.arm.Gen, Msg: timer.arm.Msg}
	return boundInput{in: consensus.Replay{Msg: timer.arm.Msg}, future: &expiry, via: "derived_future_timer_schedule", arm: &timer.source}, nil
}

// retain accepts source-verified arms in output order. A cancelled timer is
// discarded only when it provably could not have expired by the end of this
// boundary. Otherwise its queued callback remains a possible candidate.
func (b *inputBindings) retain(source inputobs.Input, outputs []consensus.Output, arms []timerBinding) error {
	at, err := time.Parse(time.RFC3339Nano, source.EndWall)
	if err != nil {
		return refusedBinding("processing_clock_unavailable")
	}
	next := 0
	retire := func(kind consensus.TimerKind) {
		kept := b.timers[:0]
		for _, timer := range b.timers {
			if timer.arm.Kind == kind && timer.live {
				// Round callbacks carry their own cancellation flag. The source
				// does not enter a processing boundary for a cancelled flag.
				if kind == consensus.RoundTimer || at.Before(timer.earliest.Add(timer.arm.Duration)) {
					continue
				}
				timer.live = false
			}
			kept = append(kept, timer)
		}
		b.timers = kept
	}
	for _, output := range outputs {
		switch value := output.(type) {
		case consensus.CancelTimers:
			for _, kind := range value.Kinds {
				retire(kind)
			}
		case consensus.ArmTimer:
			if next >= len(arms) || arms[next].arm.Gen != value.Gen || arms[next].arm.Kind != value.Kind {
				return refusedBinding("timer_arm_source_unavailable")
			}
			retire(value.Kind)
			binding := arms[next]
			binding.live = true
			b.timers = append(b.timers, binding)
			next++
		case consensus.Schedule:
			if replay, ok := value.In.(consensus.Replay); ok {
				b.replays = append(b.replays, replay.Msg)
			}
		}
	}
	if next != len(arms) || len(b.replays)+len(b.timers) > MaxProcessingRecords {
		return refusedBinding("pending_source_bindings_exceed_limit")
	}
	return nil
}
