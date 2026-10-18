package reconstruct

import (
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func TestTimerEvidenceKeepsFullBoundaryViewAndRefusesChangedPrint(t *testing.T) {
	height := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 100), big.NewInt(9))
	round := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 90), big.NewInt(3))
	h, _ := types.HeightFromBig(height)
	r, _ := types.RoundFromBig(round)
	arm := consensus.ArmTimer{Kind: consensus.RoundTimer, View: types.View{Sequence: h, Round: r}, Duration: 2 * time.Second, Gen: 3}
	source := inputobs.Input{BeginWall: "2020-01-01T00:00:00Z", EndWall: "2020-01-01T00:00:01Z", After: inputobs.View{Height: height.String(), Round: round.String()}}
	e := logs.Event{Wall: "2020-01-01T00:00:00.5Z", Line: 7, Run: "log:1", Record: event.Record{Kind: event.TimerArm, View: &event.View{Seq: "9", Round: "3"}, Fields: map[string]any{"timer": "round", "timeout": float64(2)}}}
	got, err := sourceArms(source, []consensus.Output{arm}, []logs.Event{e})
	if err != nil || len(got) != 1 || got[0].arm.View.Sequence.String() != height.String() || got[0].source.Line != 7 {
		t.Fatal("low-width print widened or source lost", got, err)
	}
	e.Record.Fields["timeout"] = float64(3)
	_, err = sourceArms(source, []consensus.Output{arm}, []logs.Event{e})
	wantBindingFailure(t, err, "timer_arm_source_differs")
	e.Record.Fields["timeout"] = float64(2)
	e.ViewInferred = true
	_, err = sourceArms(source, []consensus.Output{arm}, []logs.Event{e})
	wantBindingFailure(t, err, "timer_arm_view_unavailable")
}

func TestTimerEvidenceRefusesUnusedAndOutOfBoundaryRecords(t *testing.T) {
	source := inputobs.Input{BeginWall: "2020-01-01T00:00:00Z", EndWall: "2020-01-01T00:00:01Z"}
	e := logs.Event{Wall: "2020-01-01T00:00:00.5Z", Record: event.Record{Kind: event.TimerArm}}
	_, err := sourceArms(source, nil, []logs.Event{e})
	wantBindingFailure(t, err, "recorded_timer_arm_unused")
	e.Wall = "2020-01-01T00:00:02Z"
	_, err = sourceArms(source, nil, []logs.Event{e})
	wantBindingFailure(t, err, "timer_source_outside_processing_boundary")
}

func TestTimerEvidenceDoesNotChooseBetweenCollidingPrintedViews(t *testing.T) {
	h, _ := types.HeightFromBig(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 100), big.NewInt(9)))
	source := inputobs.Input{BeginWall: "2020-01-01T00:00:00Z", EndWall: "2020-01-01T00:00:01Z", Before: inputobs.View{Height: "9", Round: "0"}, After: inputobs.View{Height: h.String(), Round: "0"}}
	arm := consensus.ArmTimer{Kind: consensus.RoundTimer, View: types.View{Sequence: h}, Duration: 2 * time.Second}
	entry := logs.Event{Wall: "2020-01-01T00:00:00.5Z", Record: event.Record{Kind: event.TimerArm, View: &event.View{Seq: "9", Round: "0"}, Fields: map[string]any{"timer": "round", "timeout": float64(2)}}}
	_, err := sourceArms(source, []consensus.Output{arm}, []logs.Event{entry})
	wantBindingFailure(t, err, "timer_arm_view_ambiguous")
}

func TestPrintedDurationDoesNotInventNanosecondPrecision(t *testing.T) {
	if printedNanoseconds(2) != "2000000000" || printedNanoseconds(time.Duration(math.MaxInt64).Seconds()) != "" {
		t.Fatal("printed seconds widened into an exact large observation")
	}
	observed := []Projection{{Kind: "timer_arm", Timer: "round", DurationSeconds: "2"}}
	computed := []Projection{{Kind: "timer_arm", Timer: "round", DurationSeconds: "3", DurationNS: "3000000000"}}
	if len(actionDifferences(observed, computed)) != 1 {
		t.Fatal("different logged duration hidden by precision handling")
	}
}
