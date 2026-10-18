package reconstruct

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

func bindingSource(t *testing.T) (inputobs.Input, *consensus.Verified) {
	t.Helper()
	v := &consensus.Verified{Msg: &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: types.HeightFromUint64(1), Round: types.RoundFromUint64(0)}, Signature: []byte{1}}, Source: types.Address{19: 2}}
	raw, err := v.Encode()
	if err != nil {
		t.Fatal(err)
	}
	available := true
	return inputobs.Input{Kind: "backlog", Code: strconv.FormatUint(uint64(v.Msg.Code), 10), Payload: raw, PayloadSHA: sourceSHA(raw), PayloadAvailable: &available, BeginWall: "2020-01-01T00:00:05Z", EndWall: "2020-01-01T00:00:06Z"}, v
}

func wantBindingFailure(t *testing.T, err error, reason string) {
	t.Helper()
	var failure envFailure
	if !errors.As(err, &failure) || failure.Reason != reason {
		t.Fatalf("expected closed binding refusal %s, got %v", reason, err)
	}
}

func TestInputBindingsRequirePriorUniqueVerifiedReplay(t *testing.T) {
	source, verified := bindingSource(t)
	b := &inputBindings{}
	_, err := b.bind(source)
	wantBindingFailure(t, err, "backlog_source_binding_unavailable")
	b.replays = []*consensus.Verified{verified, verified}
	_, err = b.bind(source)
	wantBindingFailure(t, err, "backlog_source_binding_ambiguous")
	if len(b.replays) != 2 {
		t.Fatal("ambiguous candidates consumed")
	}
	b.replays = b.replays[:1]
	bound, err := b.bind(source)
	replay, ok := bound.in.(consensus.Replay)
	if err != nil || !ok || replay.Msg != verified || len(b.replays) != 0 || bound.future != nil {
		t.Fatal("prior verified object was replaced or not consumed", bound, err)
	}
	_, err = b.bind(source)
	wantBindingFailure(t, err, "backlog_source_binding_unavailable")
}

func TestInputBindingsKeepActualPeerAndProcessingClock(t *testing.T) {
	source, _ := bindingSource(t)
	source.Kind = "message"
	known := true
	source.PeerKnown, source.Peer = &known, "0x0000000000000000000000000000000000000002"
	source.BeginMono = "9007199254740993"
	b := &inputBindings{}
	bound, err := b.bind(source)
	message, ok := bound.in.(consensus.Message)
	if err != nil || !ok || message.RecvMono != time.Duration(9007199254740993) || message.Peer != (types.Address{19: 2}) {
		t.Fatal(bound, err)
	}
	source.BeginMono = "9223372036854775808"
	_, err = b.bind(source)
	wantBindingFailure(t, err, "processing_clock_unavailable")
	source.PeerKnown = nil
	_, err = b.bind(source)
	wantBindingFailure(t, err, "processing_peer_unavailable")
}

func TestTimerBindingRequiresUniqueDefinitelyDueSource(t *testing.T) {
	armed := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	one := timerBinding{arm: consensus.ArmTimer{Kind: consensus.RetryTimer, Gen: 4, Round: types.RoundFromUint64(3), Duration: 2 * time.Second}, earliest: armed, last: armed, live: true}
	source := inputobs.Input{Kind: "retry_timeout", TargetRound: "3", BeginWall: "2020-01-01T00:00:01Z"}
	b := &inputBindings{timers: []timerBinding{one}}
	_, err := b.bind(source)
	wantBindingFailure(t, err, "timer_source_binding_unavailable")
	source.BeginWall = "2020-01-01T00:00:03Z"
	uncertain := one
	uncertain.arm.Gen, uncertain.last = 5, armed.Add(2*time.Second)
	b.timers = append(b.timers, uncertain)
	_, err = b.bind(source)
	wantBindingFailure(t, err, "timer_source_binding_ambiguous")
	if len(b.timers) != 2 {
		t.Fatal("ambiguous expiry consumed")
	}
	b.timers = b.timers[:1]
	bound, err := b.bind(source)
	expiry, ok := bound.in.(consensus.Timeout)
	if err != nil || !ok || expiry.Gen != 4 || expiry.Round.String() != "3" || len(b.timers) != 0 {
		t.Fatal(bound, err)
	}
}

func TestCancelledRoundIsDiscardedButPossiblyQueuedRetryRemains(t *testing.T) {
	armed := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	b := &inputBindings{}
	for _, kind := range consensus.AllTimers {
		b.timers = append(b.timers, timerBinding{arm: consensus.ArmTimer{Kind: kind, Duration: time.Second}, earliest: armed, last: armed, live: true})
	}
	err := b.retain(inputobs.Input{EndWall: "2020-01-01T00:00:02Z"}, []consensus.Output{consensus.CancelTimers{Kinds: consensus.AllTimers}}, nil)
	if err != nil || len(b.timers) != 2 {
		t.Fatal("possibly queued callbacks lost or cancelled round retained", b.timers, err)
	}
	for _, timer := range b.timers {
		if timer.live || timer.arm.Kind == consensus.RoundTimer {
			t.Fatal(timer)
		}
	}
	b.timers[0].live, b.timers[1].live = true, true
	if err := b.retain(inputobs.Input{EndWall: "2020-01-01T00:00:00.5Z"}, []consensus.Output{consensus.CancelTimers{Kinds: consensus.AllTimers}}, nil); err != nil || len(b.timers) != 0 {
		t.Fatal("provably unexpired cancelled timers retained", err)
	}
}

func TestFutureBacklogIsAnExplicitBoundCompositeNotAnInventedMessage(t *testing.T) {
	source, verified := bindingSource(t)
	armed := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	timer := timerBinding{arm: consensus.ArmTimer{Kind: consensus.FutureTimer, Msg: verified, Gen: 7, View: verified.Msg.View, Duration: time.Second}, earliest: armed, last: armed, live: true}
	b := &inputBindings{timers: []timerBinding{timer}, replays: []*consensus.Verified{verified}}
	_, err := b.bind(source)
	wantBindingFailure(t, err, "backlog_source_binding_ambiguous")
	b.replays = nil
	bound, err := b.bind(source)
	if err != nil || bound.future == nil || bound.future.Msg != verified || bound.future.Gen != 7 || bound.in.(consensus.Replay).Msg != verified || len(b.timers) != 0 {
		t.Fatal(bound, err)
	}
}
