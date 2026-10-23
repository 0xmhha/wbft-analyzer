package scenario

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// This unit fixture exercises retained source projection. It does not run a
// message-change experiment or assert physical network delivery.
func TestDeferredSelectedSourceKeepsOriginalWriter(t *testing.T) {
	k, err := ecdsa.PrivateKeyFromBytes(keccak.Sum256Bytes([]byte("normal-deferred-source-test")))
	if err != nil {
		t.Fatal(err)
	}
	m := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(2), Round: types.RoundFromUint64(1)}}
	payload, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature, err = ecdsa.SignData(payload, k)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	peer := ecdsa.Address(k)
	body, err := inputlog.EncodeDeferredMessage(consensus.Message{Code: m.Code, Payload: raw, Peer: peer, RecvMono: 23}, inputlog.CaptureOrigin{Run: "first-writer", Capture: 17})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	for _, retained := range []bool{false, true} {
		dir := t.TempDir()
		runs := []string{"second-writer"}
		if retained {
			runs = append([]string{"first-writer"}, runs...)
		}
		for _, run := range runs {
			writer, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Run: run})
			if err != nil {
				t.Fatal(err)
			}
			writer.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 2, Addr: peer, Event: "attached"}})
			writer.Put(journal.Record{Body: &journal.MsgRec{Capture: 17, Dir: journal.In, PeerIdx: 2, Code: uint64(m.Code), Payload: raw, Mono: 9, Offer: transport.OfferQueued}})
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
		}
		reader, err := journal.OpenReader(nil, dir)
		if err != nil {
			t.Fatal(err)
		}
		origin, capture, deferred, err := selectedStepCapture("second-writer", &journal.StepRec{InputKind: inputlog.KindDeferredMessage, Input: body})
		if err != nil || origin != "first-writer" || capture != 17 || !deferred {
			t.Fatal("current writer replaced original capture", origin, capture, deferred, err)
		}
		if err := verifyDeferredSelection(reader, body, hex.EncodeToString(hash[:])); (err == nil) != retained {
			t.Fatalf("retained=%t: matching current packet substituted for original: %v", retained, err)
		}
	}
}
