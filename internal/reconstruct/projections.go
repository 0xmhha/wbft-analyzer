package reconstruct

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
)

const ComparisonModel = "wbft-observable-state-actions/1"

func broadcastProjection(message *codec.Message) Projection {
	digest := message.Digest
	if message.Proposal != nil && message.Proposal.Header != nil {
		digest = codec.BlockHash(message.Proposal.Header)
	}
	return Projection{Kind: "broadcast", Code: strconv.FormatUint(uint64(message.Code), 10), Height: message.View.Sequence.String(), Round: message.View.Round.String(), Digest: strings.ToLower(digest.Hex())}
}

// Action comparison covers own unsigned broadcast contents, timer arms and
// accepted sealed-header handovers. It does not claim packet delivery,
// signature equality, relay targets or application block import.
func actionProjections(source inputobs.Input, outputs []consensus.Output, rows []indexedLog, arms []timerBinding) ([]Projection, []Projection, error) {
	computed, observed := []Projection{}, []Projection{}
	for _, output := range outputs {
		switch value := output.(type) {
		case consensus.Broadcast:
			if value.Msg == nil {
				return nil, nil, refusedBinding("computed_broadcast_unavailable")
			}
			computed = append(computed, broadcastProjection(value.Msg))
		case consensus.Commit:
			if value.Block == nil || value.Block.Header == nil {
				return nil, nil, refusedBinding("computed_handover_unavailable")
			}
			computed = append(computed, Projection{Kind: "header_handover", Height: value.Block.Header.Number.String(), Round: value.Round.String(), Digest: strings.ToLower(codec.BlockHash(value.Block.Header).Hex())})
		case consensus.ArmTimer:
			computed = append(computed, Projection{Kind: "timer_arm", Timer: value.Kind.String(), Height: value.View.Sequence.String(), Round: value.View.Round.String(), DurationNS: strconv.FormatInt(value.Duration.Nanoseconds(), 10), DurationSeconds: strconv.FormatFloat(value.Duration.Seconds(), 'g', -1, 64)})
		}
	}
	// Answer lines and log lines are different coordinate domains. Their
	// relative order is not invented: compare each action class separately.
	for _, row := range rows {
		if witness := row.payload; witness != nil {
			if witness.Status != "decoded" {
				return nil, nil, refusedBinding("recorded_output_payload_unavailable")
			}
			observed = append(observed, Projection{Kind: "broadcast", Code: witness.Code, Height: witness.Height, Round: witness.Round, Digest: witness.Digest, Source: pointRef(logPoint(row.event))})
		}
	}
	for _, answer := range source.Answers {
		if answer.Method != "commit_header" || answer.Outcome != "accepted" {
			continue
		}
		block, err := codec.DecodeBlock(answer.Payload)
		if err != nil || block.Header == nil || sourceSHA(answer.Payload) != answer.PayloadSHA {
			return nil, nil, refusedBinding("recorded_handover_unavailable")
		}
		observed = append(observed, Projection{Kind: "header_handover", Height: block.Header.Number.String(), Round: source.Before.Round, Digest: strings.ToLower(codec.BlockHash(block.Header).Hex()), Source: &Point{Kind: "application_answer", File: "input_observations", Line: answer.Line, Sequence: source.Ordinal}})
	}
	for _, arm := range arms {
		observed = append(observed, arm.observed)
	}
	return observed, computed, nil
}

func pointRef(point Point) *Point { return &point }

func actionDifferences(observed, computed []Projection) []DifferenceCandidate {
	result := []DifferenceCandidate{}
	for _, kind := range []string{"broadcast", "header_handover", "timer_arm"} {
		want, got := []Projection{}, []Projection{}
		for _, value := range observed {
			if value.Kind == kind {
				want = append(want, value)
			}
		}
		for _, value := range computed {
			if value.Kind == kind {
				got = append(got, value)
			}
		}
		for i := 0; i < len(want) || i < len(got); i++ {
			var expected, actual *Projection
			if i < len(want) {
				value := want[i]
				expected = &value
			}
			if i < len(got) {
				value := got[i]
				actual = &value
			}
			left, right := expected, actual
			if left != nil {
				value := *left
				value.Source = nil
				left = &value
			}
			if right != nil {
				value := *right
				value.Source = nil
				right = &value
			}
			if left != nil && right != nil && kind == "timer_arm" && left.DurationNS == "" {
				value := *right
				value.DurationNS = ""
				right = &value
			}
			if !reflect.DeepEqual(left, right) {
				result = append(result, DifferenceCandidate{Kind: kind, Expected: expected, Actual: actual})
			}
		}
	}
	return result
}
