package reconstruct

import (
	"bytes"
	"math"
	"math/big"
	"strconv"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
)

func lowDecimal(value string) string {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok || n.Sign() < 0 || n.String() != value {
		return ""
	}
	return strconv.FormatUint(n.Uint64(), 10)
}

// A small printed duration can identify an integer nanosecond exactly. Large
// binary64 prints retain only seconds precision; they are never widened into
// a claimed exact observation of the computed nanoseconds.
func printedNanoseconds(seconds float64) string {
	nanos := seconds * 1e9
	if nanos < 0 || nanos >= 1<<52 {
		return ""
	}
	n := int64(math.Round(nanos))
	if time.Duration(n).Seconds() != seconds {
		return ""
	}
	return strconv.FormatInt(n, 10)
}

func recordedTimerView(source inputobs.Input, e logs.Event, kind consensus.TimerKind) (inputobs.View, error) {
	var found *inputobs.View
	for _, v := range []inputobs.View{source.Before, source.After} {
		if v.Height == "" || e.Record.View == nil {
			continue
		}
		matches := e.Record.View.Seq == lowDecimal(v.Height) && e.Record.View.Round == lowDecimal(v.Round) && !e.ViewInferred
		if kind == consensus.RetryTimer {
			// In this profile retry view is carried from the full-width round
			// entry, while its explicit copied round is a low-width print.
			matches = e.Record.View.Seq == v.Height && e.Record.View.Round == v.Round
		}
		if !matches {
			continue
		}
		if found != nil && (found.Height != v.Height || found.Round != v.Round) {
			return inputobs.View{}, refusedBinding("timer_arm_view_ambiguous")
		}
		copy := v
		found = &copy
	}
	if found == nil {
		return inputobs.View{}, refusedBinding("timer_arm_view_unavailable")
	}
	return *found, nil
}

// sourceArms binds computed timers to records inside the actual processing
// boundary. Printed low-width log coordinates are corroboration only; the
// full view comes from the processing snapshot, never from widening a print.
func sourceArms(source inputobs.Input, outputs []consensus.Output, entries []logs.Event) ([]timerBinding, error) {
	begin, beginErr := time.Parse(time.RFC3339Nano, source.BeginWall)
	end, endErr := time.Parse(time.RFC3339Nano, source.EndWall)
	if beginErr != nil || endErr != nil || end.Before(begin) {
		return nil, refusedBinding("processing_clock_unavailable")
	}
	observed := []logs.Event{}
	for _, e := range entries {
		at, err := time.Parse(time.RFC3339Nano, e.Wall)
		if err != nil || at.Before(begin) || at.After(end) {
			return nil, refusedBinding("timer_source_outside_processing_boundary")
		}
		if e.Record.Kind == event.TimerArm {
			observed = append(observed, e)
		}
	}
	result := []timerBinding{}
	next := 0
	for _, output := range outputs {
		arm, ok := output.(consensus.ArmTimer)
		if !ok {
			continue
		}
		if arm.Kind == consensus.FutureTimer {
			var answer *inputobs.Answer
			for i := range source.Answers {
				a := &source.Answers[i]
				if a.Method == "verify" && a.Outcome == "future" {
					if answer != nil {
						return nil, refusedBinding("future_timer_source_ambiguous")
					}
					answer = a
				}
			}
			if answer == nil || arm.Msg == nil || arm.Msg.Msg == nil {
				return nil, refusedBinding("future_timer_source_unavailable")
			}
			raw, err := codec.EncodeBlock(arm.Msg.Msg.Proposal)
			ns, parseErr := strconv.ParseInt(answer.DurationNS, 10, 64)
			at, timeErr := time.Parse(time.RFC3339Nano, answer.Wall)
			if err != nil || parseErr != nil || timeErr != nil || at.Before(begin) || at.After(end) || arm.Duration != time.Duration(ns) || !bytes.Equal(raw, answer.Payload) || sourceSHA(raw) != answer.PayloadSHA {
				return nil, refusedBinding("future_timer_source_differs")
			}
			message, decodeErr := codec.DecodeMessage(arm.Msg.Msg.Code, source.Payload)
			encoded, encodeErr := arm.Msg.Encode()
			if decodeErr != nil || encodeErr != nil || !bytes.Equal(encoded, source.Payload) || message.View.Cmp(arm.View) != 0 {
				return nil, refusedBinding("future_timer_message_differs")
			}
			point := Point{Kind: "application_answer", File: "input_observations", Line: answer.Line, Sequence: source.Ordinal}
			observed := Projection{Kind: "timer_arm", Timer: "future", Height: message.View.Sequence.String(), Round: message.View.Round.String(), DurationNS: answer.DurationNS, DurationSeconds: strconv.FormatFloat(arm.Duration.Seconds(), 'g', -1, 64), Source: pointRef(point)}
			result = append(result, timerBinding{arm: arm, source: point, observed: observed, earliest: at, last: end})
			continue
		}
		if next == len(observed) {
			return nil, refusedBinding("timer_arm_source_unavailable")
		}
		e := observed[next]
		next++
		view, err := recordedTimerView(source, e, arm.Kind)
		if err != nil {
			return nil, err
		}
		if view.Height != arm.View.Sequence.String() || view.Round != arm.View.Round.String() {
			return nil, refusedBinding("timer_arm_view_differs")
		}
		seconds, ok := e.Record.Fields["timeout"].(float64)
		if !ok || seconds != arm.Duration.Seconds() || field(e, "timer") != arm.Kind.String() {
			return nil, refusedBinding("timer_arm_source_differs")
		}
		switch arm.Kind {
		case consensus.RoundTimer:
			if e.Record.View == nil || e.ViewInferred || e.Record.View.Seq != strconv.FormatUint(arm.View.Sequence.RefLow64(), 10) || e.Record.View.Round != strconv.FormatUint(arm.View.Round.RefLow64(), 10) {
				return nil, refusedBinding("timer_arm_view_unavailable")
			}
		case consensus.RetryTimer:
			if field(e, "round") != strconv.FormatUint(arm.Round.RefLow64(), 10) {
				return nil, refusedBinding("retry_round_source_differs")
			}
		default:
			return nil, refusedBinding("timer_kind_unavailable")
		}
		at, _ := time.Parse(time.RFC3339Nano, e.Wall)
		point := logPoint(e)
		projection := Projection{Kind: "timer_arm", Timer: arm.Kind.String(), Height: view.Height, Round: view.Round, DurationNS: printedNanoseconds(seconds), DurationSeconds: strconv.FormatFloat(seconds, 'g', -1, 64), Source: pointRef(point)}
		result = append(result, timerBinding{arm: arm, source: point, observed: projection, earliest: at, last: end})
	}
	if next != len(observed) {
		return nil, refusedBinding("recorded_timer_arm_unused")
	}
	return result, nil
}

func sourceTimerFire(source inputobs.Input, entries []logs.Event) (*Point, error) {
	if source.Kind != "round_timeout" {
		// Retry delivery has an explicit copied full round in the input
		// record, but the implementation emits no separate fire phrase.
		return nil, nil
	}
	var point *Point
	for _, e := range entries {
		if e.Record.Kind != event.TimerFire || field(e, "timer") != "round" {
			continue
		}
		if point != nil || e.Record.View == nil || e.ViewInferred || e.Record.View.Seq != lowDecimal(source.Before.Height) || e.Record.View.Round != lowDecimal(source.Before.Round) {
			return nil, refusedBinding("timer_fire_source_ambiguous")
		}
		p := logPoint(e)
		point = &p
	}
	if point == nil {
		return nil, refusedBinding("timer_fire_source_unavailable")
	}
	return point, nil
}
