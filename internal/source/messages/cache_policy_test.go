package messages

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestCachePolicyHeaderCannotUseLegacyCacheProof(t *testing.T) {
	for _, legacy := range []uint64{0, journal.CacheTraceVersion} {
		in := Input{ID: "policy-journal", Kind: "journal", Node: self, Path: t.TempDir()}
		w, err := journal.Open(journal.Options{Dir: in.Path, Synchronous: true}, journal.Identity{
			Self: types.Address{19: 1}, Run: "cache-policy-writer", ChainID: big.NewInt(7),
			Core: journal.CoreOptions{CacheTrace: legacy, CachePolicy: &journal.CachePolicyOptions{
				Profile: journal.AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 16, ReceivePerPeer: 8, WritePending: 64, WritePerPeer: 16},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		rows, err := readCacheJournal(t, in)
		if err == nil || len(rows) != 0 {
			t.Fatal("new policy reused legacy cache reconstruction", legacy, err, len(rows))
		}
	}
}

type cachePolicyRecordObserver struct{ writer journal.Writer }

func (o cachePolicyRecordObserver) ObserveWriteTransition(event transport.WriteTransition) {
	o.writer.Put(journal.Record{Body: &journal.WriteCacheRec{Transition: event}})
}
func (o cachePolicyRecordObserver) ObserveReceiveTransition(event transport.ReceiveTransition) {
	o.writer.Put(journal.Record{Body: &journal.ReceiveCacheRec{Transition: event}})
}

func TestCachePolicyRecordCannotUseLegacyProofWithoutHeader(t *testing.T) {
	for _, legacy := range []uint64{0, journal.CacheTraceVersion} {
		for _, domain := range []string{"write", "receive", "session", "session_frame", "write_attempt", "core_step", "app_queue", "finalize", "inbox", "internal", "selection", "receive_dispatch", "wal_read", "restore", "signer", "signer_call"} {
			t.Run(fmt.Sprintf("%s/%d", domain, legacy), func(t *testing.T) {
				in := Input{ID: "policy-record-journal", Kind: "journal", Node: self, Path: t.TempDir()}
				writer, err := journal.Open(journal.Options{Dir: in.Path, Synchronous: true}, journal.Identity{Self: types.Address{19: 1}, Run: "policy-record-writer", ChainID: big.NewInt(7), Core: journal.CoreOptions{CacheTrace: legacy}})
				if err != nil {
					t.Fatal(err)
				}
				observer := cachePolicyRecordObserver{writer}
				switch domain {
				case "write":
					_, err = transport.NewWriteLedger(transport.WriteLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true, Trace: observer})
				case "receive":
					_, err = transport.NewReceiveLedger(transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true, Trace: observer})
				case "session":
					writer.Put(journal.Record{Body: &journal.SessionRec{Session: &journal.SessionRef{Run: "original-writer", Ordinal: 1}, Event: journal.SessionObserved, Active: true}})
				case "internal":
					writer.Put(journal.Record{Body: &journal.InternalRec{Version: journal.InternalSourceVersion, Sequence: 1, EngineRun: 1, Action: "reset"}})
				case "wal_read":
					writer.Put(journal.Record{Body: &journal.WALReadRec{Source: wal.ReadSource{Version: wal.ReadSourceVersion, Namespace: "original-reader", Log: 1, Sequence: 1}}})
				case "restore":
					writer.Put(journal.Record{Body: &journal.RestoreRec{Version: journal.RestoreSourceVersion, EngineRun: 1, Read: journal.WALReadRef{Namespace: "original-reader", Log: 1, Sequence: 1}, From: "1"}})
				case "signer":
					writer.Put(journal.Record{Body: &journal.SignerRec{Source: privval.Source{Version: privval.SourceVersion, Ref: privval.SourceRef{Namespace: "original-signer", Signer: 1, Sequence: 1}, Action: "initial", Result: "ok", Unavailable: "inspection_limits_required"}}})
				case "signer_call":
					writer.Put(journal.Record{Body: &journal.SignerCallRec{Version: journal.SignerCallSourceVersion, EngineRun: 1, Step: 1, Output: 1, Source: privval.SourceRef{Namespace: "original-signer", Signer: 1, Sequence: 2}, Result: "sent"}})
				case "receive_dispatch":
					input, e := inputlog.Encode(consensus.Message{})
					if e != nil {
						t.Fatal(e)
					}
					writer.Put(journal.Record{Body: &journal.ReceiveDispatchRec{Version: journal.ReceiveDispatchSourceVersion, Sequence: 1, Request: 1, EngineRun: 1, BeforeStep: 1, Action: "prepare", Via: "peer", Source: transport.ReceivePreparationSource{WriterRun: "original-writer", Ledger: 1, Sequence: 1}, Scope: 1, Decision: uint64(transport.ReceiveReserved), Selection: 1, InboxRequest: 1, InputKind: inputlog.KindMessage, Input: input}})
				case "selection":
					writer.Put(journal.Record{Body: &journal.SelectionRec{Version: journal.SelectionSourceVersion, Sequence: 1, Selection: 1, EngineRun: 1, Step: 1, Action: "select", Lane: "none", Internal: journal.InputProbe{State: "empty"}, App: journal.InputProbe{State: "empty"}, Timer: journal.InputProbe{State: "empty"}, Inbox: journal.InputProbe{State: "empty"}, NextHeight: "disabled"}})
				case "inbox":
					writer.Put(journal.Record{Body: &journal.InboxRec{Version: journal.InboxSourceVersion, Sequence: 1, EngineRun: 1, Step: 1, Action: "clear"}})
				case "finalize":
					writer.Put(journal.Record{Body: &journal.FinalizeRec{Version: journal.FinalizeSourceVersion, Sequence: 1, Task: 1, EngineRun: 1, Step: 1, Output: 1, Action: "return"}})
				case "app_queue":
					input, e := inputlog.Encode(consensus.PeerConnected{Addr: types.Address{3}})
					if e != nil {
						t.Fatal(e)
					}
					writer.Put(journal.Record{Body: &journal.AppQueueRec{Version: journal.AppQueueSourceVersion, Sequence: 1, Request: 1, Action: "append", InputKind: inputlog.KindPeerConnected, Input: input, After: 1}})
				case "core_step":
					input, e := inputlog.Encode(consensus.Start{})
					if e != nil {
						t.Fatal(e)
					}
					outputs, e := inputlog.EncodeOutputs(nil)
					if e != nil {
						t.Fatal(e)
					}
					digest, e := inputlog.OutDigest(nil)
					if e != nil {
						t.Fatal(e)
					}
					writer.Put(journal.Record{Body: &journal.CoreStepRec{EngineRun: 1, Step: 1, Via: "engine", InputKind: inputlog.KindStart, Input: input, Outputs: outputs, OutDigest: digest}})
				case "write_attempt":
					writer.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, WriteAttempt: &journal.WriteAttemptSource{Sequence: 1, WriterRun: "original-writer", Ledger: 1, Request: 2}}})
				case "session_frame":
					writer.Put(journal.Record{Body: &journal.MsgRec{Session: &journal.SessionRef{Run: "original-writer", Ordinal: 1}, Dir: journal.In}})
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				rows, err := readCacheJournal(t, in)
				if domain == "internal" && !errors.Is(err, errInternalSource) {
					t.Fatal("internal source used the wrong refusal boundary", err)
				}
				for name, want := range map[string]error{"wal_read": errWALReadSource, "restore": errRestoreSource, "signer": errSignerSource, "signer_call": errSignerCallSource} {
					if domain == name && !errors.Is(err, want) {
						t.Fatal("unsupported source used the wrong refusal boundary", domain, err)
					}
				}
				if domain == "receive_dispatch" && !errors.Is(err, errReceiveDispatchSource) {
					t.Fatal("receive disposition source used the wrong refusal boundary", err)
				}
				if domain == "selection" && !errors.Is(err, errSelectionSource) {
					t.Fatal("selection source used the wrong refusal boundary", err)
				}
				if domain == "inbox" && !errors.Is(err, errInboxSource) {
					t.Fatal("inbox source used the wrong refusal boundary", err)
				}
				if domain == "finalize" && !errors.Is(err, errFinalizeSource) {
					t.Fatal("application finalization source used the wrong refusal boundary", err)
				}
				if domain == "app_queue" && !errors.Is(err, errAppQueueSource) {
					t.Fatal("application queue source used the wrong refusal boundary", err)
				}
				if err == nil || len(rows) != 0 {
					t.Fatal("unsupported cache kind exposed a legacy prefix", domain, legacy, len(rows), err)
				}
			})
		}
	}
}
