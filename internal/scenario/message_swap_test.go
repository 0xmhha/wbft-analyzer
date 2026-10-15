package scenario

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestSelectedMessageSwapRetainsActualJournalCoreInputs(t *testing.T) {
	sc := timingFixture(t)
	sc.Seed = 1
	baselineDir := t.TempDir()
	if _, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: baselineDir}); err != nil {
		t.Fatal(err)
	}
	var selectors []sim.MessageSelector
	for _, v := range sc.Validators {
		dir := filepath.Join(baselineDir, strings.TrimPrefix(strings.ToLower(v.Address().Hex()), "0x"))
		reader, err := journal.OpenReader(nil, dir)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := journal.ReadAll(nil, dir)
		if err != nil {
			t.Fatal(err)
		}
		run := ""
		for _, record := range rows {
			if segment, ok := record.Body.(*journal.SegmentRec); ok {
				run = segment.Run
				continue
			}
			message, ok := record.Body.(*journal.MsgRec)
			if !ok || message.Dir != journal.In || message.Code != uint64(codec.CodePrepare) || message.Capture == 0 {
				continue
			}
			verified, err := consensus.Recover(codec.Code(message.Code), message.Payload, nil)
			if err != nil {
				t.Fatal(err)
			}
			if verified.Msg.View.Sequence.String() != "1" || verified.Msg.View.Round.String() != "0" || len(selectors) > 0 && selectors[0].Signer == verified.Source {
				continue
			}
			frame, err := reader.ResolveCapture(run, message.Capture)
			if err != nil {
				t.Fatal(err)
			}
			selectors = append(selectors, sim.MessageSelector{Peer: frame.Peer, Receiver: v.Address(), Signer: verified.Source, Code: codec.CodePrepare, Sequence: "1", Round: "0", Occurrence: 1})
			if len(selectors) == 2 {
				break
			}
		}
		if len(selectors) == 2 {
			break
		}
		selectors = nil
	}
	if len(selectors) != 2 {
		t.Fatal("fixture lacks two distinct signed deliveries")
	}
	sc.MessageChanges = []sim.MessageDeliveryChange{{Kind: sim.MessageSwap, First: selectors[0], Second: &selectors[1]}}
	dir := t.TempDir()
	result, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := observedMessages(context.Background(), sc, result, dir)
	if err != nil || len(observed.Changes) != 1 {
		t.Fatal(observed, err)
	}
	x := observed.Changes[0]
	if x.Status != "applied" || x.First == nil || x.Second == nil {
		t.Fatal(x)
	}
	for _, packet := range []*SeedMessageDelivery{x.First, x.Second} {
		if packet.ReleasedNS == nil || *packet.ReleasedNS < packet.SentNS || packet.Capture == 0 || packet.Offer != "queued" || len(packet.CoreInputs) != 1 || packet.CoreInputs[0].EntryNS == nil {
			t.Fatal("actual input proof missing", packet)
		}
	}
	if (x.First.Arrival < x.Second.Arrival) == (x.First.Release < x.Second.Release) {
		t.Fatal("relative delivery order unchanged", x)
	}
	// Transport order is deliberately not asserted as global core FIFO.
	// The reported core coordinates are read through each capture's writer run.
	original := result.MessageDeliveries[0].First.Capture
	result.MessageDeliveries[0].First.Capture = ^uint64(0)
	if _, err := observedMessages(context.Background(), sc, result, dir); err == nil {
		t.Fatal("missing capture manufactured core evidence")
	}
	result.MessageDeliveries[0].First.Capture = original
	originalRun := result.MessageDeliveries[0].First.ReceiverRun
	result.MessageDeliveries[0].First.ReceiverRun = "foreign-run"
	if _, err := observedMessages(context.Background(), sc, result, dir); err == nil {
		t.Fatal("capture crossed receiver run")
	}
	result.MessageDeliveries[0].First.ReceiverRun = originalRun
	result.MessageDeliveries[0].First.PayloadSHA256[0] ^= 1
	if _, err := observedMessages(context.Background(), sc, result, dir); err == nil {
		t.Fatal("capture disagreed with the selected payload")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := simulateMessageSeed(ctx, sc); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation converted to a selection result", err)
	}
}
