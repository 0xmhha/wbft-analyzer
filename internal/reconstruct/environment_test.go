package reconstruct

import (
	"bytes"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

func answerWithBytes(method, outcome string, raw []byte) inputobs.Answer {
	available := true
	return inputobs.Answer{Method: method, Outcome: outcome, Payload: raw, PayloadSHA: sourceSHA(raw), PayloadAvailable: &available}
}

func wantEnvironmentFailure(t *testing.T, reason string, call func()) {
	t.Helper()
	defer func() {
		failure, ok := recover().(envFailure)
		if !ok || failure.Reason != reason {
			t.Fatalf("expected closed environment refusal %q, got %#v", reason, failure)
		}
	}()
	call()
	t.Fatal("unrecorded or conflicting answer was supplied")
}

func environmentFixture(t *testing.T) (*observedEnv, *types.Block, inputobs.Answer, inputobs.Answer) {
	t.Helper()
	addresses := []types.Address{{19: 1}, {19: 2}}
	policy := uint64(0)
	cfg := types.NewConfig(types.WBFTParams{EpochLength: 10, ProposerPolicy: &policy}, nil, types.GenesisInit{}, big.NewInt(7))
	block := &types.Block{Header: &types.Header{Number: types.HeightFromUint64(0), Difficulty: big.NewInt(1)}, Body: types.BodyRaw{{0xc0}, {0xc0}}}
	extra := &types.WBFTExtra{VanityData: make([]byte, 32), RandaoReveal: []byte{}, EpochInfo: &types.EpochInfo{Candidates: []types.Candidate{{Addr: addresses[0]}, {Addr: addresses[1]}}, Validators: []uint32{0, 1}, BLSPublicKeys: [][]byte{{1}, {2}}}}
	if err := codec.SetExtra(block.Header, extra); err != nil {
		t.Fatal(err)
	}
	chain, err := sim.NewChainSource([]*types.Block{block})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	head := answerWithBytes("head", "available", raw)
	head.HeadProposer = addresses[1].Hex()
	// Hand-authored application set in source order, independent of the lookup.
	setRaw, err := rlp.Encode([]any{uint64(0), []any{[]any{addresses[0], []byte{1}}, []any{addresses[1], []byte{2}}}})
	if err != nil {
		t.Fatal(err)
	}
	set := answerWithBytes("validators_at", "available", setRaw)
	set.ArgumentSHA = sourceSHA(raw)
	return &observedEnv{chain: chain.Reader(), cfg: cfg}, block, head, set
}

func TestObservedEnvironmentUsesExactHeadAndOfficialValidatorLookup(t *testing.T) {
	e, block, head, set := environmentFixture(t)
	e.reset([]inputobs.Answer{head, set})
	got := e.Head()
	if got.Proposer != (types.Address{19: 2}) || !bytes.Equal(got.Header.Extra, block.Header.Extra) {
		t.Fatal("recorded head context replaced", got)
	}
	vs, err := e.ValidatorsAt(types.HeightFromUint64(1), codec.BlockHash(block.Header))
	if err != nil || vs.Len() != 2 || vs.At(0).Addr != (types.Address{19: 1}) || vs.At(1).BLSPublicKey[0] != 2 || e.finish() != nil {
		t.Fatal(vs, err, e.finish())
	}
	// Keep the node-local sealed fields even when their filtered block hash is
	// identical to the archival header's hash.
	local := &types.Block{Header: block.Header.Copy(), Body: block.Body}
	x, err := codec.DecodeExtra(local.Header)
	if err != nil {
		t.Fatal(err)
	}
	x.Round = 7
	if err = codec.SetExtra(local.Header, x); err != nil {
		t.Fatal(err)
	}
	if codec.BlockHash(local.Header) != codec.BlockHash(block.Header) {
		t.Fatal("fixture does not exercise a node-local header variant")
	}
	raw, _ := codec.EncodeBlock(local)
	head = answerWithBytes("head", "available", raw)
	head.HeadProposer = (types.Address{19: 2}).Hex()
	e.reset([]inputobs.Answer{head})
	got = e.Head()
	if !bytes.Equal(got.Header.Extra, local.Header.Extra) || bytes.Equal(got.Header.Extra, block.Header.Extra) {
		t.Fatal("archive substituted for actual node-local head")
	}
}

func TestObservedEnvironmentRefusesMissingReorderedAndUnusedAnswers(t *testing.T) {
	e, block, head, _ := environmentFixture(t)
	wantEnvironmentFailure(t, "application_answer_unavailable", func() { e.Head() })
	e.reset([]inputobs.Answer{head})
	wantEnvironmentFailure(t, "application_call_order_differs", func() { _, _ = e.ValidateProposal(block) })
	var unused envFailure
	if !errors.As(e.finish(), &unused) || unused.Reason != "recorded_application_answer_unused" {
		t.Fatal("unused source answer disappeared", e.finish())
	}
	head.PayloadAvailable = nil
	e.reset([]inputobs.Answer{head})
	wantEnvironmentFailure(t, "application_payload_unavailable", func() { e.Head() })
}

func TestObservedEnvironmentBindsValidatorQueryAndRecordedSet(t *testing.T) {
	for _, change := range []string{"height", "parent", "argument", "members"} {
		e, block, head, set := environmentFixture(t)
		n, parent := types.HeightFromUint64(1), codec.BlockHash(block.Header)
		want := "validator_query_differs"
		switch change {
		case "height":
			n = types.HeightFromUint64(2)
		case "parent":
			parent = types.Hash{1}
		case "argument":
			set.ArgumentSHA = sourceSHA([]byte("foreign"))
		case "members":
			set = answerWithBytes("validators_at", "available", []byte{0xc0})
			set.ArgumentSHA = sourceSHA(head.Payload)
			want = "validator_answer_differs"
		}
		e.reset([]inputobs.Answer{head, set})
		e.Head()
		wantEnvironmentFailure(t, want, func() { _, _ = e.ValidatorsAt(n, parent) })
	}
}

func TestObservedEnvironmentPreservesExplicitVerificationAndBadBlockResults(t *testing.T) {
	_, block, _, _ := environmentFixture(t)
	raw, _ := codec.EncodeBlock(block)
	for _, outcome := range []string{"accepted", "future", "rejected"} {
		a := answerWithBytes("verify", outcome, raw)
		a.DurationNS = "-7"
		e := &observedEnv{}
		e.reset([]inputobs.Answer{a})
		duration, err := e.ValidateProposal(block)
		if duration != -7*time.Nanosecond || outcome == "accepted" && err != nil || outcome == "future" && !errors.Is(err, header.ErrFutureBlock) || outcome == "rejected" && err != errRecordedRejection || e.finish() != nil {
			t.Fatal(outcome, duration, err)
		}
		e.reset([]inputobs.Answer{a})
		foreign := &types.Block{Header: block.Header.Copy(), Body: block.Body}
		foreign.Header.Time++
		wantEnvironmentFailure(t, "application_argument_differs", func() { _, _ = e.ValidateProposal(foreign) })
	}
	for _, bad := range []bool{false, true} {
		e := &observedEnv{}
		hash := codec.BlockHash(block.Header)
		e.reset([]inputobs.Answer{{Method: "bad_block", SubjectHash: hash.Hex(), Bad: &bad}})
		if e.IsBadBlock(hash) != bad {
			t.Fatal("bad-block result changed")
		}
		e.reset([]inputobs.Answer{{Method: "bad_block", SubjectHash: hash.Hex(), Bad: &bad}})
		wantEnvironmentFailure(t, "bad_block_argument_differs", func() { e.IsBadBlock(types.Hash{9}) })
	}
}

func TestObservedEnvironmentNeverInventsCommitSuccess(t *testing.T) {
	_, block, _, _ := environmentFixture(t)
	raw, _ := codec.EncodeBlock(block)
	// Literal empty seal groups and full round form the recorded argument.
	argument, _ := rlp.Encode([]any{raw, []any{}, []any{}, big.NewInt(1)})
	a := inputobs.Answer{Method: "commit_header", Outcome: "rejected", ArgumentSHA: sourceSHA(argument)}
	e := &observedEnv{}
	e.reset([]inputobs.Answer{a})
	if b, err := e.CommitHeader(block, types.RoundFromUint64(1), nil, nil, nil); b != nil || err != errRecordedRejection {
		t.Fatal(b, err)
	}
	e.reset([]inputobs.Answer{a})
	wantEnvironmentFailure(t, "commit_header_argument_differs", func() { _, _ = e.CommitHeader(block, types.RoundFromUint64(2), nil, nil, nil) })
	a = answerWithBytes("commit_header", "accepted", raw)
	a.ArgumentSHA = sourceSHA(argument)
	e.reset([]inputobs.Answer{a})
	// The source claims success, but empty seals fail the actual linked header
	// implementation. Preserve that disagreement instead of returning the block.
	wantEnvironmentFailure(t, "commit_header_result_differs", func() { _, _ = e.CommitHeader(block, types.RoundFromUint64(1), nil, nil, nil) })
}
