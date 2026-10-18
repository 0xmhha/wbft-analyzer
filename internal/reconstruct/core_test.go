package reconstruct

import (
	"errors"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

func coreFixture(t *testing.T) (*observedCore, inputobs.Input) {
	t.Helper()
	e, _, head, set := environmentFixture(t)
	c := newObservedCore(e.cfg, types.Address{19: 1}, e.chain)
	return c, inputobs.Input{Ordinal: "1", Instance: "1", Kind: "start", Answers: []inputobs.Answer{head, set}}
}

func TestObservedCoreExecutesLinkedCoreWithAllImprovementsOff(t *testing.T) {
	c, start := coreFixture(t)
	if out, err := c.step(start, consensus.Start{}); err != nil || len(out) == 0 {
		t.Fatal("actual linked start did not execute", out, err)
	}
	if c.state.Options().Improvements != 0 || !c.state.Snapshot().Running || c.state.Snapshot().View.Sequence.String() != "1" {
		t.Fatal("core configuration or actual start state differs")
	}
	if _, err := c.step(inputobs.Input{Ordinal: "2", Instance: "1", Kind: "stop"}, consensus.Stop{}); err != nil || c.state.Running() {
		t.Fatal("actual stop did not execute", err)
	}
}

func TestObservedCoreDiscardsOutputsAndCannotResumeAfterMissingAnswer(t *testing.T) {
	c, start := coreFixture(t)
	start.Answers = start.Answers[:1]
	out, err := c.step(start, consensus.Start{})
	var failure envFailure
	if len(out) != 0 || !errors.As(err, &failure) || failure.Reason != "application_answer_unavailable" {
		t.Fatal("partial engine outputs escaped", out, err)
	}
	before := c.state.Snapshot()
	_, err = c.step(inputobs.Input{Ordinal: "2", Instance: "1", Kind: "stop"}, consensus.Stop{})
	if !errors.As(err, &failure) || failure.Reason != "application_answer_unavailable" || c.state.Snapshot().Running != before.Running {
		t.Fatal("failed partially mutated engine was resumed", err)
	}
}

func TestObservedCoreRefusesUnusedAnswerAndUnboundSequence(t *testing.T) {
	for _, change := range []string{"unused", "gap", "instance", "restart"} {
		c, start := coreFixture(t)
		if _, err := c.step(start, consensus.Start{}); err != nil {
			t.Fatal(err)
		}
		next := inputobs.Input{Ordinal: "2", Instance: "1", Kind: "stop"}
		var in consensus.Input = consensus.Stop{}
		want := ""
		switch change {
		case "unused":
			next.Answers = start.Answers[:1]
			want = "recorded_application_answer_unused"
		case "gap":
			next.Ordinal = "3"
			want = "processing_input_sequence_unbound"
		case "instance":
			next.Instance = "2"
			want = "processing_engine_instance_differs"
		case "restart":
			in = consensus.Start{}
			want = "processing_engine_restart_unbound"
		}
		out, err := c.step(next, in)
		var failure envFailure
		if len(out) != 0 || !errors.As(err, &failure) || failure.Reason != want || c.failed == nil {
			t.Fatal(change, out, err)
		}
	}
}

func TestObservedCorePreservesGlobalSourceOrdinalAcrossInstances(t *testing.T) {
	c, start := coreFixture(t)
	// A later instance starts after earlier instances' source ordinals. Its
	// reconstructed ordinal is separate and must not replace this coordinate.
	start.Ordinal, start.Instance = "31", "2"
	if _, err := c.step(start, consensus.Start{}); err != nil || c.ordinal != 31 || c.instance != "2" {
		t.Fatal("source ordinal was reset for the reconstructed engine", err)
	}
	if _, err := c.step(inputobs.Input{Ordinal: "32", Instance: "2", Kind: "stop"}, consensus.Stop{}); err != nil {
		t.Fatal(err)
	}
}

func TestObservedCoreFutureCompositeHasOneSourceOrdinalAndAtomicAnswers(t *testing.T) {
	for _, missing := range []bool{false, true} {
		c, start := coreFixture(t)
		if _, err := c.step(start, consensus.Start{}); err != nil {
			t.Fatal(err)
		}
		snapshot := c.state.Snapshot()
		proposal := &types.Block{Header: c.env.head.Copy(), Body: types.BodyRaw{{0xc0}, {0xc0}}}
		proposal.Header.ParentHash = codec.BlockHash(c.env.head)
		proposal.Header.Number = types.HeightFromUint64(1)
		verified := &consensus.Verified{Msg: &codec.Message{Code: codec.CodePreprepare, View: snapshot.View, Proposal: proposal}, Source: snapshot.Proposer}
		raw, err := codec.EncodeBlock(proposal)
		if err != nil {
			t.Fatal(err)
		}
		answer := answerWithBytes("verify", "accepted", raw)
		answer.DurationNS = "0"
		source := inputobs.Input{Ordinal: "2", Instance: "1", Kind: "backlog", Answers: []inputobs.Answer{answer}}
		if missing {
			source.Answers = nil
		}
		binding := boundInput{in: consensus.Replay{Msg: verified}, future: &consensus.Timeout{Kind: consensus.FutureTimer, Gen: 7, Msg: verified}}
		out, err := c.apply(source, binding)
		if missing {
			wantBindingFailure(t, err, "application_answer_unavailable")
			if len(out) != 0 || c.failed == nil {
				t.Fatal("derived output escaped the failed observed boundary")
			}
			continue
		}
		if err != nil || c.ordinal != 2 || c.state.Snapshot().State != consensus.Preprepared || len(c.state.Vars().Prepares) != 0 {
			t.Fatal("source ordinal reset or a broadcast delivered automatically", out, err)
		}
		for _, output := range out {
			if _, queued := output.(consensus.Schedule); queued {
				t.Fatal("already bound derived replay was queued a second time")
			}
		}
	}
}
