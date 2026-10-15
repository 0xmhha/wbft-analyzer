package scenario

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestRecordedMessageSelectionContract(t *testing.T) {
	valid := `{"kind":"drop_message","from_ns":0,"to_ns":60000000000,"messages":[{"input":"journal-1","file":"00000000000000000001.wal","ordinal":"9007199254740993","model_occurrence":"18446744073709551615"}]}`
	var change NetworkChange
	if err := json.Unmarshal([]byte(valid), &change); err != nil {
		t.Fatal(err)
	}
	if change.Messages[0].Ordinal != 9007199254740993 || change.Messages[0].Occurrence != ^uint64(0) {
		t.Fatal("rounded selection", change)
	}
	canonical, hash, err := change.Canonical()
	var again NetworkChange
	if err != nil || json.Unmarshal(canonical, &again) != nil {
		t.Fatal(err)
	}
	_, second, _ := again.Canonical()
	if hash != second {
		t.Fatal("selection hash drift")
	}
	for _, invalid := range []string{
		strings.Replace(valid, `"ordinal":"9007199254740993"`, `"ordinal":9007199254740993`, 1),
		strings.Replace(valid, `"model_occurrence":"18446744073709551615"`, `"model_occurrence":"01"`, 1),
		strings.Replace(valid, `"ordinal":"9007199254740993"`, `"ordinal":"01"`, 1),
		strings.Replace(valid, `"model_occurrence":"18446744073709551615"`, `"model_occurrence":null`, 1),
		strings.Replace(valid, `"file":"00000000000000000001.wal"`, `"file":"../foreign"`, 1),
		strings.Replace(valid, `"kind":"drop_message"`, `"kind":"swap_messages"`, 1),
		strings.Replace(valid, `"messages":[`, `"Messages":[`, 1),
		strings.Replace(valid, `"messages":[`, `"node":null,"messages":[`, 1),
		strings.Replace(valid, `"messages":[`, `"effective_selector":{},"messages":[`, 1),
	} {
		if json.Unmarshal([]byte(invalid), &again) == nil {
			t.Fatalf("accepted %s", invalid)
		}
	}
	sc := timingFixture(t)
	before, _ := ExecutionHash(sc)
	if _, _, err := ApplyNetworkChange(sc, change); err == nil {
		t.Fatal("unbound native selection accepted")
	}
	if after, _ := ExecutionHash(sc); after != before {
		t.Fatal("baseline mutated")
	}
}

func TestRecordedMessageBindingVerifiesRelaySignerAndFullWidthView(t *testing.T) {
	sc := timingFixture(t)
	large, _ := new(big.Int).SetString("1208925819614629174706176", 10)
	round, err := types.RoundFromBig(large)
	if err != nil {
		t.Fatal(err)
	}
	msg := &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: types.MustHeightFromBig(large), Round: round}, Digest: types.Hash{1}}
	key := sc.Validators[2]
	signing, err := codec.SigningPayload(msg, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdsa.PrivateKeyFromBytes(key.ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	msg.Signature, err = ecdsa.SignData(signing, private)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(payload)
	row := messages.Record{Input: "wire", File: "frame.jsonl", Ordinal: 3, Node: sc.Validators[1].Address().Hex(), Peer: sc.Validators[0].Address().Hex(), Signer: key.Address().Hex(), Type: "frame", Dir: "in", PeerStatus: "recorded", Decode: "decoded", Signature: "recovered", Height: large.String(), Round: large.String(), Phase: "PREPARE", PayloadSHA256: hex.EncodeToString(hash[:])}
	addresses := []string{}
	for _, v := range sc.Validators {
		addresses = append(addresses, v.Address().Hex())
	}
	ref := RecordedMessageSelection{Input: row.Input, File: row.File, Ordinal: row.Ordinal, Occurrence: 2}
	bound, err := BindRecordedMessage(ref, row, payload, 0x13, addresses)
	if err != nil || bound.Effective.Peer != 0 || bound.Effective.Signer != 2 || bound.Effective.Receiver != 1 || bound.Effective.Height != large.String() {
		t.Fatal(bound, err)
	}
	change := NetworkChange{Kind: "drop_message", ToNS: int64(sc.Until.Duration), Messages: []RecordedMessageSelection{ref}}
	before, _ := ExecutionHash(sc)
	changed, effect, _, err := ApplyMessageChange(sc, change, []RecordedMessageBinding{bound})
	if err != nil || effect == nil || changed.MessageChanges[0].First.Occurrence != 2 || changed.MessageChanges[0].First.Sequence != large.String() {
		t.Fatal(effect, err)
	}
	after, _ := ExecutionHash(sc)
	altered, _ := ExecutionHash(changed)
	if before != after || before == altered {
		t.Fatal("identity did not distinguish intervention")
	}
	if effect.ExecutionSHA256 != altered {
		t.Fatal("effective execution identity disagrees")
	}
	duplicateRow := row
	duplicateRow.Ordinal++
	duplicateRef := ref
	duplicateRef.Ordinal++
	duplicateBound, err := BindRecordedMessage(duplicateRef, duplicateRow, payload, 0x13, addresses)
	if err != nil {
		t.Fatal(err)
	}
	overlap := NetworkChange{Kind: "swap_messages", ToNS: int64(sc.Until.Duration), Messages: []RecordedMessageSelection{ref, duplicateRef}}
	if _, _, _, err := ApplyMessageChange(sc, overlap, []RecordedMessageBinding{bound, duplicateBound}); err == nil {
		t.Fatal("different source copies overlapped the same model occurrence")
	}
	for _, alter := range []func(*messages.Record){func(r *messages.Record) { r.Signer = r.Peer }, func(r *messages.Record) { r.Dir = "out" }, func(r *messages.Record) { r.PayloadSHA256 = strings.Repeat("0", 64) }, func(r *messages.Record) { r.Phase = "COMMIT" }, func(r *messages.Record) { r.Height = "1" }} {
		bad := row
		alter(&bad)
		if _, err := BindRecordedMessage(ref, bad, payload, 0x13, addresses); err == nil {
			t.Fatal("unproved binding accepted", bad)
		}
	}
	// A recovered outer signer does not establish justification signatures.
	msg.Code = codec.CodeRoundChange
	msg.Prepares = []*codec.Message{{Code: codec.CodePrepare, View: msg.View, Digest: msg.Digest, Signature: []byte{1}}}
	signing, err = codec.SigningPayload(msg, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg.Signature, err = ecdsa.SignData(signing, private)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = codec.EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	hash = sha256.Sum256(payload)
	row.Phase, row.PayloadSHA256 = "ROUND-CHANGE", hex.EncodeToString(hash[:])
	if _, err := BindRecordedMessage(ref, row, payload, 0x15, addresses); err == nil {
		t.Fatal("invalid embedded signature accepted from recovered outer projection")
	}
}

func TestRecordedMessageBindingKeepsOfficialFrameBoundaries(t *testing.T) {
	sc := timingFixture(t)
	message := &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: types.HeightFromUint64(2)}, Seal: make([]byte, transport.MaxFramePayload)}
	private, err := ecdsa.PrivateKeyFromBytes(sc.Validators[2].ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := codec.SigningPayload(message, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	message.Signature, err = ecdsa.SignData(signed, private)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.EncodeMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consensus.Recover(codec.CodePrepare, payload, nil); err != nil || len(payload) <= transport.MaxFramePayload {
		t.Fatal("frame boundary positive control invalid", err)
	}
	hash := sha256.Sum256(payload)
	row := messages.Record{Input: "wire", File: "frames-a.jsonl", Ordinal: 1, Node: sc.Validators[1].Address().Hex(), Peer: sc.Validators[0].Address().Hex(), Signer: sc.Validators[2].Address().Hex(), Type: "frame", Dir: "in", PeerStatus: "recorded", Decode: "decoded", Signature: "recovered", Height: "2", Round: "0", Phase: "PREPARE", PayloadSHA256: hex.EncodeToString(hash[:])}
	addresses := []string{}
	for _, v := range sc.Validators {
		addresses = append(addresses, v.Address().Hex())
	}
	if _, err := BindRecordedMessage(RecordedMessageSelection{Input: row.Input, File: row.File, Ordinal: row.Ordinal, Occurrence: 1}, row, payload, 0x13, addresses); err == nil {
		t.Fatal("valid signatures bypassed the official frame limit")
	}
}

func TestSelectedMessageSeedsKeepUnmatchedEvidenceAndContinue(t *testing.T) {
	sc := timingFixture(t)
	sc.MessageChanges = []sim.MessageDeliveryChange{{Kind: sim.MessageDrop, First: sim.MessageSelector{Peer: sc.Validators[0].Address(), Receiver: sc.Validators[1].Address(), Signer: sc.Validators[2].Address(), Code: codec.CodePrepare, Sequence: "999", Round: "0", Occurrence: 1}}}
	var got []SeedResult
	err := RunSeeds(context.Background(), sc, []int64{1, 2}, 1, 3, func(r SeedResult) error { got = append(got, r); return nil })
	if err != nil || len(got) != 2 {
		t.Fatal(len(got), err)
	}
	for _, r := range got {
		if r.Status != "partial" || r.Execution.Messages == nil || r.Execution.Messages.Changes[0].Status != "unmatched" || r.Execution.Messages.Changes[0].First != nil || len(r.Heights) != 3 {
			t.Fatal("missing selection became success or lost real result", r)
		}
	}
}

func TestSelectedMessageObservationsFollowRealCaptureAndCoreInput(t *testing.T) {
	sc := timingFixture(t)
	sc.Seed = 1
	dir := t.TempDir()
	baseline, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	var selector sim.MessageSelector
	found := false
	for receiver, v := range sc.Validators {
		reader, err := journal.OpenReader(nil, filepath.Join(dir, strings.TrimPrefix(strings.ToLower(v.Address().Hex()), "0x")))
		if err != nil {
			t.Fatal(err)
		}
		rows, err := journal.ReadAll(nil, filepath.Join(dir, strings.TrimPrefix(strings.ToLower(v.Address().Hex()), "0x")))
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range rows {
			m, ok := record.Body.(*journal.MsgRec)
			if !ok || m.Dir != journal.In || m.Code != 0x13 || m.Capture == 0 {
				continue
			}
			var run string
			for _, r := range rows {
				if s, ok := r.Body.(*journal.SegmentRec); ok {
					run = s.Run
					break
				}
			}
			frame, err := reader.ResolveCapture(run, m.Capture)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := consensus.Recover(codec.Code(m.Code), m.Payload, nil)
			if err != nil {
				t.Fatal(err)
			}
			selector = sim.MessageSelector{Peer: frame.Peer, Receiver: sc.Validators[receiver].Address(), Signer: verified.Source, Code: codec.Code(m.Code), Sequence: verified.Msg.View.Sequence.String(), Round: verified.Msg.View.Round.String(), Occurrence: 1}
			found = true
			break
		}
		if found {
			break
		}
	}
	if !found || len(baseline.Chain) == 0 {
		t.Fatal("fixture has no candidate")
	}
	// A swap of two occurrences of the same tuple uses a later occurrence
	// that is deliberately absent: the first packet stays held, not delivered.
	second := selector
	second.Occurrence = 1000000
	sc.MessageChanges = []sim.MessageDeliveryChange{{Kind: sim.MessageSwap, First: selector, Second: &second}}
	result, observed, err := simulateMessageSeed(context.Background(), sc)
	if result == nil || err == nil || observed == nil || observed.Changes[0].Status != "incomplete_pair" || observed.Changes[0].First.ReleasedNS != nil || observed.Changes[0].First.Capture != 0 || len(observed.Changes[0].First.CoreInputs) != 0 {
		t.Fatal("held packet acquired fake receiver or handler", observed, err)
	}
	// Dropping the same candidate removes one copy and retains exact wire proof.
	sc.MessageChanges = []sim.MessageDeliveryChange{{Kind: sim.MessageDrop, First: selector}}
	_, observed, err = simulateMessageSeed(context.Background(), sc)
	if err != nil || observed.Changes[0].Status != "applied" || observed.Changes[0].First.ReleasedNS != nil || observed.Changes[0].First.Offer != "" {
		t.Fatal(observed, err)
	}
}
