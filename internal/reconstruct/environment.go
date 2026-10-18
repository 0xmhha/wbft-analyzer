package reconstruct

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
	"github.com/ethereum/go-ethereum/common"
)

var errRecordedRejection = errors.New("recorded application rejection")

// envFailure stops this engine before any unrecorded application result is
// supplied. Its fields are closed metadata and never include raw errors.
type envFailure struct {
	Reason, Method         string
	ExpectedSHA, ActualSHA string
}

func (envFailure) Error() string { return "reconstructed application binding refused" }

type observedEnv struct {
	chain   types.ChainReader
	cfg     *types.Config
	answers []inputobs.Answer
	next    int
	head    *types.Header
	headRaw []byte
}

var _ consensus.Env = (*observedEnv)(nil)

func (e *observedEnv) reset(answers []inputobs.Answer) {
	e.answers, e.next = answers, 0
}

func (e *observedEnv) take(method string) inputobs.Answer {
	if e.next >= len(e.answers) {
		panic(envFailure{Reason: "application_answer_unavailable", Method: method})
	}
	a := e.answers[e.next]
	if a.Method != method {
		panic(envFailure{Reason: "application_call_order_differs", Method: method})
	}
	e.next++
	return a
}

func (e *observedEnv) finish() error {
	if e.next != len(e.answers) {
		return envFailure{Reason: "recorded_application_answer_unused", Method: e.answers[e.next].Method}
	}
	return nil
}

func sourceSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func requireAnswerPayload(a inputobs.Answer) {
	if a.PayloadAvailable == nil || !*a.PayloadAvailable || sourceSHA(a.Payload) != a.PayloadSHA {
		panic(envFailure{Reason: "application_payload_unavailable", Method: a.Method})
	}
}

func requireSamePayload(a inputobs.Answer, raw []byte) {
	requireAnswerPayload(a)
	if !bytes.Equal(a.Payload, raw) {
		panic(envFailure{Reason: "application_argument_differs", Method: a.Method, ExpectedSHA: a.PayloadSHA, ActualSHA: sourceSHA(raw)})
	}
}

func (e *observedEnv) Head() consensus.HeadInfo {
	a := e.take("head")
	requireAnswerPayload(a)
	if a.Outcome != "available" || !addressPattern.MatchString(a.HeadProposer) {
		panic(envFailure{Reason: "head_answer_unavailable", Method: a.Method})
	}
	b, err := codec.DecodeBlock(a.Payload)
	if err != nil || b.Header == nil || !b.Header.Number.IsUint64() || e.chain == nil || !e.chain.HasBlock(codec.BlockHash(b.Header), b.Header.Number.Big().Uint64()) {
		panic(envFailure{Reason: "head_chain_identity_unbound", Method: a.Method})
	}
	e.head, e.headRaw = b.Header.Copy(), append([]byte(nil), a.Payload...)
	return consensus.HeadInfo{Header: b.Header, Proposer: common.HexToAddress(a.HeadProposer)}
}

// The observed node-local head takes precedence over the archival copy. The
// archive supplies ancestry, never a replacement for recorded head bytes.
type observedHeadChain struct {
	types.ChainReader
	head *types.Header
}

func (c observedHeadChain) Head() *types.Header { return c.head }
func (c observedHeadChain) Header(h types.Hash, n uint64) *types.Header {
	if c.head.Number.IsUint64() && c.head.Number.Big().Uint64() == n && codec.BlockHash(c.head) == h {
		return c.head
	}
	return c.ChainReader.Header(h, n)
}
func (c observedHeadChain) HeaderByNumber(n uint64) *types.Header {
	if c.head.Number.IsUint64() && c.head.Number.Big().Uint64() == n {
		return c.head
	}
	return c.ChainReader.HeaderByNumber(n)
}
func (c observedHeadChain) HeaderByHash(h types.Hash) *types.Header {
	if codec.BlockHash(c.head) == h {
		return c.head
	}
	return c.ChainReader.HeaderByHash(h)
}
func (c observedHeadChain) HasBlock(h types.Hash, n uint64) bool { return c.Header(h, n) != nil }

func encodedValidators(vs *validator.Set) ([]byte, error) {
	members := make([]any, vs.Len())
	for i := 0; i < vs.Len(); i++ {
		v := vs.At(i)
		members[i] = []any{v.Addr, v.BLSPublicKey}
	}
	return rlp.Encode([]any{vs.Policy().ID, members})
}

func (e *observedEnv) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	a := e.take("validators_at")
	requireAnswerPayload(a)
	if a.Outcome != "available" || e.head == nil || e.cfg == nil || n.Cmp(e.head.Number.AddUint64(1)) != 0 || parent != codec.BlockHash(e.head) || a.ArgumentSHA != sourceSHA(e.headRaw) {
		panic(envFailure{Reason: "validator_query_differs", Method: a.Method})
	}
	vs, err := validator.ValidatorsAt(observedHeadChain{ChainReader: e.chain, head: e.head}, e.cfg, n, parent, nil)
	if err != nil || vs == nil {
		panic(envFailure{Reason: "validator_context_unavailable", Method: a.Method})
	}
	raw, err := encodedValidators(vs)
	if err != nil {
		panic(envFailure{Reason: "validator_context_unavailable", Method: a.Method})
	}
	if !bytes.Equal(raw, a.Payload) {
		panic(envFailure{Reason: "validator_answer_differs", Method: a.Method, ExpectedSHA: a.PayloadSHA, ActualSHA: sourceSHA(raw)})
	}
	return vs, nil
}

func (e *observedEnv) ValidateProposal(b *types.Block) (time.Duration, error) {
	a := e.take("verify")
	raw, err := codec.EncodeBlock(b)
	if err != nil {
		panic(envFailure{Reason: "proposal_argument_unavailable", Method: a.Method})
	}
	requireSamePayload(a, raw)
	ns, err := strconv.ParseInt(a.DurationNS, 10, 64)
	if err != nil {
		panic(envFailure{Reason: "proposal_duration_unavailable", Method: a.Method})
	}
	duration := time.Duration(ns)
	switch a.Outcome {
	case "accepted":
		return duration, nil
	case "future":
		return duration, header.ErrFutureBlock
	case "rejected":
		return duration, errRecordedRejection
	default:
		panic(envFailure{Reason: "proposal_answer_unavailable", Method: a.Method})
	}
}

func (e *observedEnv) IsBadBlock(h types.Hash) bool {
	a := e.take("bad_block")
	if a.Bad == nil || !hashPattern.MatchString(a.SubjectHash) || common.HexToHash(a.SubjectHash) != h {
		panic(envFailure{Reason: "bad_block_argument_differs", Method: a.Method})
	}
	return *a.Bad
}

func commitArguments(b *types.Block, round types.Round, prepared, committed []types.SealEntry) (string, error) {
	proposal, err := codec.EncodeBlock(b)
	if err != nil {
		return "", err
	}
	normalize := func(seals []types.SealEntry) []any {
		copied := append([]types.SealEntry(nil), seals...)
		sort.Slice(copied, func(i, j int) bool {
			if copied[i].Sealer != copied[j].Sealer {
				return copied[i].Sealer < copied[j].Sealer
			}
			return bytes.Compare(copied[i].Seal, copied[j].Seal) < 0
		})
		items := make([]any, len(copied))
		for i, seal := range copied {
			items[i] = []any{uint64(seal.Sealer), seal.Seal}
		}
		return items
	}
	raw, err := rlp.Encode([]any{proposal, normalize(prepared), normalize(committed), round.Big()})
	if err != nil {
		return "", err
	}
	return sourceSHA(raw), nil
}

func (e *observedEnv) CommitHeader(b *types.Block, round types.Round, _ *validator.Set, prepared, committed []types.SealEntry) (*types.Block, error) {
	a := e.take("commit_header")
	argument, err := commitArguments(b, round, prepared, committed)
	if err != nil || a.ArgumentSHA != argument {
		panic(envFailure{Reason: "commit_header_argument_differs", Method: a.Method, ExpectedSHA: a.ArgumentSHA, ActualSHA: argument})
	}
	if a.Outcome == "rejected" {
		return nil, errRecordedRejection
	}
	if a.Outcome != "accepted" {
		panic(envFailure{Reason: "commit_header_answer_unavailable", Method: a.Method})
	}
	requireAnswerPayload(a)
	sealed, err := header.CommitHeader(b, round, prepared, committed)
	if err != nil {
		panic(envFailure{Reason: "commit_header_result_differs", Method: a.Method})
	}
	raw, err := codec.EncodeBlock(sealed)
	if err != nil || !bytes.Equal(raw, a.Payload) {
		panic(envFailure{Reason: "commit_header_result_differs", Method: a.Method, ExpectedSHA: a.PayloadSHA, ActualSHA: sourceSHA(raw)})
	}
	return sealed, nil
}
