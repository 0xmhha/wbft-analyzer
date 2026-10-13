package missing

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/events"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
)

func TestNormalizedInboundLossCannotProveSenderAbsence(t *testing.T) {
	for _, what := range []string{"peer_inbound_overflow", "peer_inbound_disconnect"} {
		t.Run(what, func(t *testing.T) {
			rows, inputs := coverageRows(address(1))
			if c := runCell(t, baseHeight(), rows, nil, inputs); c.Class != "NOT_SENT" {
				t.Fatal(c)
			}
			value, err := json.Marshal(what)
			if err != nil {
				t.Fatal(err)
			}
			fields := events.Metadata(map[string]json.RawMessage{"kind": json.RawMessage(`"HEALTH"`), "what": value})
			rows = append(rows, native(address(1), 4, event.Health, "", "", fields))
			if c := runCell(t, baseHeight(), rows, nil, inputs); c.Class != "UNKNOWN" {
				t.Fatal("input loss became an absence proof", c)
			}
		})
	}
}

func address(i int) string { return fmt.Sprintf("0x%040x", i) }
func baseHeight() Height {
	return Height{Index: "1", Number: "1", Round: "0", Hash: "0x" + strings.Repeat("a", 64), ChildHash: "0x" + strings.Repeat("b", 64), ChildParentHash: "0x" + strings.Repeat("a", 64), Validators: []string{address(1), address(2), address(3), address(4)}}
}
func native(node string, line int64, kind event.Kind, h, r string, fields map[string]any) logs.Event {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["seq"] = strconv.FormatInt(line-1, 10)
	var v *event.View
	if h != "" {
		v = &event.View{Seq: h, Round: r}
	}
	return logs.Event{Node: node, Input: node, Run: "run", Line: line, Wall: "2020-01-01T00:00:00Z", Profile: logs.EventProfile, Record: event.Record{Src: "event", Kind: kind, View: v, Fields: fields}}
}
func coverageRows(nodes ...string) ([]logs.Event, []Input) {
	var rows []logs.Event
	var inputs []Input
	for _, n := range nodes {
		rows = append(rows, native(n, 1, event.NodeStart, "", "", map[string]any{"validator": true}), native(n, 2, event.RoundEnter, "1", "0", nil), native(n, 3, event.RoundEnter, "2", "0", nil))
		inputs = append(inputs, Input{ID: n, Complete: true})
	}
	return rows, inputs
}
func runCell(t *testing.T, h Height, rows []logs.Event, records []source.Record, ins []Input) Cell {
	t.Helper()
	cells, e := Build([]Height{h}, rows, records, ins)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range cells {
		if c.Validator == address(1) && c.Phase == "PREPARE" {
			return c
		}
	}
	t.Fatal("cell missing")
	return Cell{}
}
func send(key string) logs.Event {
	return native(address(1), 4, event.Send, "", "", map[string]any{"code": "19", "cause": "broadcast", "dedup_key": key})
}
func receive(node, key, outcome string) logs.Event {
	return native(node, 4, event.MsgOutcome, "1", "0", map[string]any{"code": "19", "dedup_key": key, "source": address(1), "peer": address(4), "outcome": outcome})
}
func decoded(key string) []source.Record {
	return []source.Record{{Type: "frame", Decode: "decoded", Phase: "PREPARE", Height: "1", Round: "0", Key: key, Signer: address(1)}}
}

func TestHeaderPriorityAndForkBinding(t *testing.T) {
	h := baseHeight()
	h.Seals = []Seal{{Validator: address(1), Phase: "PREPARE", Index: "2", Hash: h.ChildHash, Round: "0", Basis: "previous"}}
	if c := runCell(t, h, nil, nil, nil); c.Class != "SEALED" {
		t.Fatal(c)
	}
	h.ChildParentHash = "foreign"
	if c := runCell(t, h, nil, nil, nil); c.Class != "UNKNOWN" {
		t.Fatal("foreign child proved a seal", c)
	}
	h.Seals = []Seal{{Validator: address(1), Phase: "PREPARE", Index: "1", Hash: h.Hash, Round: "1", Basis: "own"}}
	if c := runCell(t, h, nil, nil, nil); c.Class != "SEALED" || c.Seals[0].Round != "1" {
		t.Fatal("own copy round lost", c)
	}
	h.Seals[0].Hash = "foreign"
	if c := runCell(t, h, nil, nil, nil); c.Class != "UNKNOWN" {
		t.Fatal("foreign own copy accepted", c)
	}
}
func TestAuthorAndExactByteIdentity(t *testing.T) {
	key := "k"
	rows := []logs.Event{send(key), receive(address(2), key, "ACCEPT")}
	c := runCell(t, baseHeight(), rows, nil, nil)
	if c.Class != "SENT_ACCEPTED_NOT_SEALED" || c.Accepted != 1 || c.Sends != 1 {
		t.Fatal(c)
	}
	// The transporting peer is address(4), while the author is address(1).
	rows[1].Record.Fields["source"] = address(3)
	if c := runCell(t, baseHeight(), rows, decoded(key), nil); c.Class != "UNKNOWN" {
		t.Fatal("peer or contradictory author substituted", c)
	}
	rows[1] = receive(address(2), "other", "ACCEPT")
	if c := runCell(t, baseHeight(), rows, decoded(key), nil); c.Class != "UNKNOWN" || c.Reason != "unlinked_receipt" {
		t.Fatal("different byte key linked", c)
	}
}
func TestRecordedRejectAndUnknownOutcome(t *testing.T) {
	for _, result := range []string{"IGNORE", "DROP_SILENT", "DISCONNECT"} {
		c := runCell(t, baseHeight(), []logs.Event{send("k"), receive(address(2), "k", result)}, nil, nil)
		if c.Class != "SENT_REJECTED" || c.Rejected != 1 {
			t.Fatal(c)
		}
	}
	if c := runCell(t, baseHeight(), []logs.Event{send("k"), receive(address(2), "k", "IGNORE"), receive(address(3), "k", "unavailable")}, nil, nil); c.Class != "UNKNOWN" {
		t.Fatal(c)
	}
}
func TestUnseenNeedsQuorumOfClosedCleanNativeViews(t *testing.T) {
	rows, ins := coverageRows(address(1), address(2), address(3))
	rows = append(rows, send("k"))
	c := runCell(t, baseHeight(), rows, decoded("k"), ins)
	if c.Class != "SENT_UNSEEN" || c.ReceiverCoverage != 3 || c.Quorum != 3 {
		t.Fatal(c)
	}
	for _, change := range []func(*Input){func(i *Input) { i.Complete = false }, func(i *Input) { i.Stats.SequenceGaps = 1 }, func(i *Input) { i.Stats.Malformed = 1 }} {
		copyInputs := append([]Input(nil), ins...)
		change(&copyInputs[2])
		c = runCell(t, baseHeight(), rows, decoded("k"), copyInputs)
		if c.Class != "UNKNOWN" || c.ReceiverCoverage != 2 {
			t.Fatal("incomplete receiver counted", c)
		}
	}
	rows = append(rows, native(address(3), 5, event.Health, "", "", map[string]any{"what": "peer_inbound_overflow"}))
	if c := runCell(t, baseHeight(), rows, decoded("k"), ins); c.Class != "UNKNOWN" {
		t.Fatal("queue loss used for absence", c)
	}
}
func TestNotSentNeedsRecordedCoverageAndPreservesFloor(t *testing.T) {
	rows, ins := coverageRows(address(1))
	c := runCell(t, baseHeight(), rows, nil, ins)
	if c.Class != "NOT_SENT" || c.Reason != "closed_native_view" {
		t.Fatal(c)
	}
	rows[0].Record.Fields["sign_floor_height"] = "18446744073709551617"
	rows[0].Record.Fields["sign_floor_status"] = "kept"
	c = runCell(t, baseHeight(), rows, nil, ins)
	if c.Class != "NOT_SENT" || c.Reason != "sign_floor" {
		t.Fatal(c)
	}
	found := false
	for _, e := range c.Evidence {
		if e.Role == "sign_floor" && e.Source.Ordinal == 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("floor source missing")
	}
	rows[0].Record.Fields["sign_floor_status"] = "cleared"
	if c := runCell(t, baseHeight(), rows, nil, ins); c.Reason == "sign_floor" {
		t.Fatal("cleared floor remained active", c)
	}
	if c := runCell(t, baseHeight(), rows[:2], nil, ins); c.Class != "UNKNOWN" {
		t.Fatal("open view claimed absence", c)
	}
	for i := range rows {
		rows[i].Record.Src = "log"
	}
	if c := runCell(t, baseHeight(), rows, nil, ins); c.Class != "UNKNOWN" {
		t.Fatal("legacy logs proved send absence", c)
	}
}
func TestReceiptWithoutSendIsNotAbsence(t *testing.T) {
	rows, ins := coverageRows(address(1))
	rows = append(rows, receive(address(2), "k", "ACCEPT"))
	if c := runCell(t, baseHeight(), rows, nil, ins); c.Class != "UNKNOWN" || c.UnlinkedReceipts != 1 {
		t.Fatal("receipt became NOT_SENT", c)
	}
}
func TestWeakTupleCollisionsRemainUnknown(t *testing.T) {
	e := logs.Event{Node: address(1), Input: "legacy", Run: "r", Line: 1, Record: event.Record{Src: "log", Kind: event.Send, Fields: map[string]any{"phase": "PREPARE", "msg.sequence": "1", "msg.round": "0"}}}
	recs := decoded("k")
	c := runCell(t, baseHeight(), []logs.Event{e, receive(address(2), "k", "ACCEPT")}, recs, nil)
	if c.Class != "SENT_ACCEPTED_NOT_SEALED" || c.Strength != "key" {
		t.Fatal(c)
	}
	extra := native(address(3), 1, event.RoundEnter, "18446744073709551617", "0", nil)
	if c := runCell(t, baseHeight(), []logs.Event{e, receive(address(2), "k", "ACCEPT"), extra}, recs, nil); c.Class != "UNKNOWN" || c.Reason != "ambiguous_identity" {
		t.Fatal("full-height low64 collision hidden", c)
	}
	if c := runCell(t, baseHeight(), []logs.Event{e, receive(address(2), "k", "ACCEPT"), receive(address(3), "k2", "ACCEPT")}, nil, nil); c.Class != "UNKNOWN" {
		t.Fatal("two byte identities became one weak vote", c)
	}
}
func TestFullViewAndBoundedEvidenceCounts(t *testing.T) {
	h := baseHeight()
	h.Number = "18446744073709551617"
	h.Round = "340282366920938463463374607431768211456"
	r := receive(address(2), "k", "ACCEPT")
	r.Record.View = &event.View{Seq: h.Number, Round: h.Round}
	rows := []logs.Event{send("k")}
	for i := 0; i < 40; i++ {
		x := r
		x.Line = int64(i + 1)
		rows = append(rows, x)
	}
	c := runCell(t, h, rows, nil, nil)
	if c.Class != "SENT_ACCEPTED_NOT_SEALED" || c.Height != h.Number || c.Round != h.Round || c.Accepted != 40 || c.EvidenceCount != 41 || len(c.Evidence) != 32 {
		t.Fatal(c)
	}
}

func TestReopenedViewAndUnidentifiedReceiveCannotProveAbsence(t *testing.T) {
	rows, ins := coverageRows(address(1), address(2), address(3))
	unknown := receive(address(3), "k", "ACCEPT")
	delete(unknown.Record.Fields, "source")
	if c := runCell(t, baseHeight(), append(rows, send("missing"), unknown), decoded("missing"), ins); c.Class != "UNKNOWN" || c.ReceiverCoverage != 2 {
		t.Fatal("unidentified receive claimed full coverage", c)
	}
	rows = append(rows, native(address(1), 4, event.RoundEnter, "1", "0", nil))
	if c := runCell(t, baseHeight(), rows, nil, ins); c.Class != "UNKNOWN" {
		t.Fatal("reopened view used earlier closed proof", c)
	}
}

func TestKnownPrefilterDuplicateDoesNotEraseCoverage(t *testing.T) {
	rows, ins := coverageRows(address(1), address(2), address(3))
	duplicate := native(address(3), 4, event.MsgOutcome, "", "", map[string]any{"code": "19", "check": "prefilter", "dedup_key": "other", "outcome": "DROP_SILENT"})
	records := append(decoded("missing"), source.Record{Type: "frame", Decode: "decoded", Key: "other", Phase: "PREPARE", Height: "1", Round: "0", Signer: address(4)})
	if c := runCell(t, baseHeight(), append(rows, send("missing"), duplicate), records, ins); c.Class != "SENT_UNSEEN" || c.ReceiverCoverage != 3 {
		t.Fatal("known duplicate became a source gap", c)
	}
}

func TestCompleteActiveCaptureCoversSkippedCoreHeights(t *testing.T) {
	h := baseHeight()
	h.Number = "2"
	before, after := baseHeight(), baseHeight()
	before.Number = "1"
	after.Number = "3"
	after.Hash = "0x" + strings.Repeat("c", 64)
	rows := []logs.Event{native(address(1), 1, event.NodeStart, "", "", map[string]any{"validator": true}), native(address(1), 2, event.NewHead, "1", "0", map[string]any{"hash": before.Hash}), native(address(1), 3, event.NewHead, "3", "0", map[string]any{"hash": after.Hash}), native(address(1), 4, event.NodeStop, "", "", nil)}
	ins := []Input{{ID: address(1), Complete: true}}
	target := func(events []logs.Event, input []Input) Cell {
		cells, e := Build([]Height{before, h, after}, events, nil, input)
		if e != nil {
			t.Fatal(e)
		}
		for _, c := range cells {
			if c.Height == "2" && c.Validator == address(1) && c.Phase == "PREPARE" {
				return c
			}
		}
		t.Fatal("target absent")
		return Cell{}
	}
	if c := target(rows, ins); c.Class != "NOT_SENT" || c.Reason != "complete_active_event_capture" || c.ReceiverCoverage != 0 || c.EvidenceCount != 4 {
		t.Fatal(c)
	}
	if c := target(rows[:3], ins); c.Class != "UNKNOWN" {
		t.Fatal("live prefix claimed capture end", c)
	}
	rows[0].Record.Fields["validator"] = false
	if c := target(rows, ins); c.Class != "UNKNOWN" {
		t.Fatal("observer headers proved sender absence", c)
	}
	rows[0].Record.Fields["validator"] = true
	rows[2].Record.Fields["hash"] = "foreign"
	if c := target(rows, ins); c.Class != "UNKNOWN" {
		t.Fatal("foreign upper head proved coverage", c)
	}
	rows[2].Record.Fields["hash"] = after.Hash
	opaque := native(address(1), 5, event.Send, "", "", map[string]any{"code": "19", "cause": "broadcast", "dedup_key": "opaque"})
	if c := target(append(rows, opaque), ins); c.Class != "UNKNOWN" || c.Reason != "unpositioned_sender_identity" {
		t.Fatal("opaque SEND became NOT_SENT", c)
	}
}

func TestLateEarlierHeightSendDoesNotBorrowCurrentView(t *testing.T) {
	rows, ins := coverageRows(address(1))
	extra := native(address(1), 4, event.Send, "", "", map[string]any{"code": "20", "cause": "extra_seal", "dedup_key": "earlier"})
	records := []source.Record{{Type: "frame", Decode: "decoded", Key: "earlier", Phase: "COMMIT", Height: "0", Round: "0", Signer: address(1)}}
	cells, e := Build([]Height{baseHeight()}, append(rows, extra), records, ins)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range cells {
		if c.Validator == address(1) && c.Phase == "COMMIT" && c.Class != "NOT_SENT" {
			t.Fatal("current view substituted for message identity", c)
		}
	}
}

func TestRangeBoundsCellsBeforeAllocationAndKeepsCanonicalHeads(t *testing.T) {
	heights := make([]Height, 12501)
	for i := range heights {
		h := baseHeight()
		h.Index = fmt.Sprint(i + 1)
		h.Number = h.Index
		heights[i] = h
	}
	if _, e := Build(heights, nil, nil, nil); e == nil {
		t.Fatal("unbounded cell allocation accepted")
	}
	cells, e := BuildRange(heights, nil, nil, nil, 2, 2)
	if e != nil || len(cells) != 8 {
		t.Fatal("range bound failed", len(cells), e)
	}
	node := address(4)
	wall := "2020-01-01T00:00:00Z"
	rows := []logs.Event{}
	for i, k := range []event.Kind{event.NodeStart, event.NewHead, event.NewHead, event.NodeStop} {
		fields := map[string]any{"seq": fmt.Sprint(i), "validator": true}
		var v *event.View
		if k == event.NewHead {
			number := "1"
			if i == 2 {
				number = "3"
			}
			v = &event.View{Seq: number, Round: "0"}
			fields["hash"] = heights[0].Hash
		}
		rows = append(rows, logs.Event{Input: "events", Node: node, Run: "r", Line: int64(i + 1), Wall: wall, Record: event.Record{Src: "event", Kind: k, View: v, Fields: fields}})
	}
	cells, e = BuildRange(heights[:3], rows, nil, []Input{{ID: "events", Complete: true}}, 2, 2)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range cells {
		if c.Validator == node && (c.Class != "NOT_SENT" || c.Reason != "complete_active_event_capture") {
			t.Fatal("outside-range canonical heads lost", c)
		}
	}
}
