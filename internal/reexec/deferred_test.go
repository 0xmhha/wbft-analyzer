package reexec

import (
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// This adapter tests the journal reader against real core outputs and a
// normally decided chain. It does not model receive-worker or WAL execution.
type deferredCoreEnv struct {
	blocks     *sim.ChainSource
	cfg        *types.Config
	head       *types.Header
	unexpected bool
}

func (e *deferredCoreEnv) Head() consensus.HeadInfo {
	return consensus.HeadInfo{Header: e.head, Proposer: types.ProposerOf(e.head)}
}
func (e *deferredCoreEnv) ValidatorsAt(n types.Height, p types.Hash) (*validator.Set, error) {
	return validator.ValidatorsAt(e.blocks.Reader(), e.cfg, n, p, nil)
}
func (e *deferredCoreEnv) ValidateProposal(*types.Block) (time.Duration, error) {
	e.unexpected = true
	return 0, fmt.Errorf("unexpected proposal")
}
func (e *deferredCoreEnv) IsBadBlock(types.Hash) bool { e.unexpected = true; return false }
func (e *deferredCoreEnv) CommitHeader(b *types.Block, r types.Round, _ *validator.Set, p, c []types.SealEntry) (*types.Block, error) {
	e.unexpected = true
	return header.CommitHeader(b, r, p, c)
}

func TestDeferredClosedReplayRetainedAndPrunedOrigin(t *testing.T) {
	source, chain, genesis := simulationInput(t)
	rd, err := journal.OpenReader(nil, source.Input.Path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	options := record.Body.(*journal.SegmentRec).Core
	options.NextHeight = &journal.DeferredOptions{Profile: journal.DeferredInputProfile, Entries: 12, Bytes: 1 << 20, PerPeer: 4, PerSource: 3}
	cfg, err := options.Configuration()
	if err != nil {
		t.Fatal(err)
	}
	chainRaw, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := sim.DecodeChain(chainRaw)
	if err != nil {
		t.Fatal(err)
	}
	blockSource, err := sim.NewChainSource(blocks)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdsa.PrivateKeyFromBytes(keccak.Sum256Bytes([]byte("closed-replay-test-1")))
	if err != nil {
		t.Fatal(err)
	}
	m := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(2), Round: types.RoundFromUint64(1)}}
	signing, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature, err = ecdsa.SignData(signing, k)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	message := consensus.Message{Code: m.Code, Payload: raw, Peer: ecdsa.Address(k), RecvMono: 23}
	var functional []string
	for _, retained := range []bool{true, false} {
		t.Run(fmt.Sprint(retained), func(t *testing.T) {
			dir := t.TempDir()
			open := func(run string) *journal.FileWriter {
				t.Helper()
				w, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Self: options.Self, Run: run, ChainID: big.NewInt(sim.ChainID), GenesisHash: codec.BlockHash(blocks[0].Header), Core: options})
				if err != nil {
					t.Fatal(err)
				}
				return w
			}
			capture := func(w *journal.FileWriter, mono time.Duration) {
				w.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 2, Addr: message.Peer, Event: "attached"}})
				w.Put(journal.Record{Body: &journal.MsgRec{Capture: 17, Dir: journal.In, PeerIdx: 2, Code: uint64(m.Code), Payload: raw, Mono: mono, Offer: transport.OfferQueued}})
			}
			if retained {
				w := open("first-writer")
				capture(w, 9)
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			}
			w := open("second-writer")
			// A later normal receipt of the same packet cannot replace its origin.
			capture(w, 90)
			env := &deferredCoreEnv{blocks: blockSource, cfg: cfg, head: blocks[1].Header}
			core := consensus.NewState(consensus.Options{Config: cfg, Self: options.Self, Improvements: consensus.ImprovementSet(options.Improvements), BacklogLimit: int(options.BacklogLimit)})
			start, err := inputlog.Encode(consensus.Start{})
			if err != nil {
				t.Fatal(err)
			}
			body, err := inputlog.EncodeDeferredMessage(message, inputlog.CaptureOrigin{Run: "first-writer", Capture: 17})
			if err != nil {
				t.Fatal(err)
			}
			for i, in := range []consensus.Input{consensus.Start{}, message} {
				outputs := core.Step(env, in)
				digest, err := inputlog.OutDigest(outputs)
				if err != nil {
					t.Fatal(err)
				}
				kind, input, via := inputlog.KindStart, start, "engine"
				if i == 1 {
					kind, input, via = inputlog.KindDeferredMessage, body, "peer"
				}
				w.Put(journal.Record{Body: &journal.StepRec{EngineRun: 1, Step: uint64(i + 1), Mono: time.Duration(100 + i*10), InputKind: kind, Input: input, Via: via, HeadNumber: env.head.Number, HeadHash: codec.BlockHash(env.head), ValsetDigest: consensus.ValsetDigest(core.Snapshot().Validators), OutDigest: digest}})
			}
			if env.unexpected {
				t.Fatal("unexpected application work in empty round change")
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			input := messages.Input{ID: "deferred", Kind: "journal", Node: strings.ToLower(options.Self.Hex()), Path: dir}
			summary, err := messages.Fingerprint(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			prepared := messages.Prepared{Input: input, Summary: summary}
			var projected *messages.DeferredEvidence
			_, err = messages.Read(t.Context(), prepared, "8282", genesis, func(r messages.Record) error {
				if r.DeferredOrigin != nil {
					projected = r.DeferredOrigin
					if r.Run != "second-writer" || r.Capture != "" {
						return fmt.Errorf("capture rebound")
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if projected == nil || projected.Origin.WriterRun != "first-writer" || projected.Origin.CaptureID != "17" {
				t.Fatalf("projected origin: %+v", projected)
			}
			plan, err := Inspect(t.Context(), prepared, chain, "8282", genesis, 2, 2)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Steps) != 2 || plan.Heights[0].Status != "complete" {
				t.Fatalf("functional plan: %+v", plan.Heights)
			}
			origin := plan.Steps[1].DeferredOrigin
			if origin == nil || retained && (origin.Status != "verified" || origin.ReceiptMono == nil || *origin.ReceiptMono != "9") || !retained && (origin.Status != "unavailable" || origin.Reason != "missing_capture" || origin.ReceiptMono != nil) {
				t.Fatalf("source status: %+v", origin)
			}
			var replayed []string
			result, err := Execute(t.Context(), plan, testHelper(t, "core"), func(step Step) error {
				if step.Class != "match" {
					return fmt.Errorf("step: %+v", step)
				}
				replayed = append(replayed, step.Replayed)
				return nil
			})
			if err != nil || result.Matches != 2 || result.Mismatches != 0 || result.NotComparable != 0 {
				t.Fatalf("closed replay: %+v %v", result, err)
			}
			if retained {
				functional = replayed
			} else if strings.Join(functional, ",") != strings.Join(replayed, ",") {
				t.Fatal("physical retention changed functional replay")
			}
		})
	}
}
