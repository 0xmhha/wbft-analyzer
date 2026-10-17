package reconstruct

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

func requestFixture(t *testing.T) *processingFixture {
	t.Helper()
	f := newProcessingFixture(t, wideHeight)
	request := map[string]any{"t": processingWall(3), "lvl": "debug", "msg": "WBFT: handle block proposal request", "address": f.self, "current.sequence": wideHeight, "current.round": "0"}
	f.rows = append(f.rows[:2], append([]map[string]any{request}, f.rows[2:]...)...)
	return f
}

func TestProposalRequestRetainsExactOwnBodyCoordinates(t *testing.T) {
	f := requestFixture(t)
	out := assessProcessing(t, f, wideHeight)
	if len(out.Heights[0].Requests) != 1 {
		t.Fatal(out.Heights[0])
	}
	r := out.Heights[0].Requests[0]
	if r.Status != "linked_proposal_source" || r.Height != wideHeight || r.Round != "0" || r.Request.Line != 3 || r.PayloadCount != 1 || r.BodySource == nil || r.BodySource.Source.Line != 4 || r.MessageHandler == nil || r.MessageHandler.Line != 6 || r.CoreInputReady || out.CoreExecuted || out.Heights[0].Status != "partial" {
		t.Fatal(r, out)
	}
	raw, err := hex.DecodeString(f.rows[3]["payload"].(string)[2:])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if r.BodySource.PayloadSHA256 != hex.EncodeToString(sum[:]) || r.BodySource.Peer != f.self {
		t.Fatal(r.BodySource)
	}
	encoded, _ := json.Marshal(out)
	for _, secret := range []string{hex.EncodeToString(raw), f.m.Log.Path, f.m.Frames.Path} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("request source bytes or path escaped")
		}
	}
}

func TestProposalRequestNeverSubstitutesMissingOrConflictingBodies(t *testing.T) {
	tests := []struct {
		name, status string
		change       func(*processingFixture)
	}{
		{"missing body", "body_unavailable", func(f *processingFixture) { f.rows = append(f.rows[:3], f.rows[4:]...) }},
		{"missing request context", "invalid_context", func(f *processingFixture) { delete(f.rows[2], "current.sequence"); delete(f.rows[2], "current.round") }},
		{"different request node", "invalid_context", func(f *processingFixture) { f.rows[2]["address"] = f.peer }},
		{"malformed body", "invalid_proposal_source", func(f *processingFixture) { f.rows[3]["payload"] = "0xc0" }},
		{"different request height", "invalid_proposal_source", func(f *processingFixture) { f.rows[2]["current.sequence"] = "1" }},
		{"different request round", "invalid_proposal_source", func(f *processingFixture) { f.rows[2]["current.round"] = "1" }},
		{"equal wall time", "invalid_proposal_source", func(f *processingFixture) { f.rows[2]["t"] = f.rows[3]["t"] }},
		{"no declared scope", "unbound_scope", func(f *processingFixture) { f.m.Scopes = nil }},
		{"request outside scope", "outside_scope", func(f *processingFixture) { f.m.Scopes[0].From = processingWall(4) }},
		{"duplicate proposal body", "ambiguous_proposal_source", func(f *processingFixture) {
			row := copyFields(f.rows[3])
			row["t"] = processingWall(5)
			f.rows = append(f.rows[:4], append([]map[string]any{row}, f.rows[4:]...)...)
		}},
		{"intervening message", "unbound_message", func(f *processingFixture) {
			row := copyFields(f.rows[7])
			row["t"] = processingWall(5)
			f.rows = append(f.rows[:4], append([]map[string]any{row}, f.rows[4:]...)...)
		}},
		{"intervening round", "unbound_message", func(f *processingFixture) {
			row := copyFields(f.rows[0])
			row["t"] = processingWall(5)
			f.rows = append(f.rows[:4], append([]map[string]any{row}, f.rows[4:]...)...)
		}},
		{"intervening request", "unbound_message", func(f *processingFixture) {
			row := copyFields(f.rows[2])
			row["t"] = processingWall(5)
			f.rows = append(f.rows[:4], append([]map[string]any{row}, f.rows[4:]...)...)
		}},
		{"intervening timeout", "unbound_message", func(f *processingFixture) {
			row := map[string]any{"t": processingWall(5), "lvl": "warn", "msg": "WBFT: TIMER CHANGING ROUND", "address": f.self, "current.sequence": wideHeight, "current.round": "0"}
			f.rows = append(f.rows[:4], append([]map[string]any{row}, f.rows[4:]...)...)
		}},
		{"intervening engine", "unbound_message", func(f *processingFixture) {
			row := map[string]any{"t": processingWall(5), "lvl": "info", "msg": "WBFT: start", "address": f.self}
			f.rows = append(f.rows[:4], append([]map[string]any{row}, f.rows[4:]...)...)
		}},
		{"unfinished message processing", "unbound_message", func(f *processingFixture) { f.rows = f.rows[:5] }},
		{"intervening head handler", "unbound_message", func(f *processingFixture) {
			row := map[string]any{"t": processingWall(5), "lvl": "info", "msg": "WBFT: handle final committed", "address": f.self, "current.sequence": wideHeight, "current.round": "0"}
			f.rows = append(f.rows[:4], append([]map[string]any{row}, f.rows[4:]...)...)
		}},
		{"intervening seal role", "unbound_message", func(f *processingFixture) {
			row := map[string]any{"t": processingWall(5), "lvl": "trace", "msg": "WBFT: new extra prepare seal message", "address": f.self, "current.sequence": wideHeight, "current.round": "0"}
			f.rows = append(f.rows[:4], append([]map[string]any{row}, f.rows[4:]...)...)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := requestFixture(t)
			test.change(f)
			// Keep the full-width request selection when a contradictory
			// request declares another height: it must not inherit a body.
			if test.name == "different request height" {
				out, err := Assess(t.Context(), f.write(t), "1", "1")
				if err != nil || len(out.Heights[0].Requests) != 1 || out.Heights[0].Requests[0].Status != test.status {
					t.Fatal(out, err)
				}
				return
			}
			out := assessProcessing(t, f, wideHeight)
			if len(out.Heights[0].Requests) == 0 {
				t.Fatal(out)
			}
			r := out.Heights[0].Requests[0]
			if r.Status != test.status || r.BodySource != nil || r.MessageHandler != nil || r.CoreInputReady || out.CoreExecuted {
				t.Fatal(r, out)
			}
		})
	}
}

func TestProposalRequestCountsUnknownHeightAndSharesSourceBound(t *testing.T) {
	f := requestFixture(t)
	p := newProcessing(f.m, map[string]int{wideHeight: 0})
	e := logs.Event{Record: event.Record{Kind: event.BuildRequest}}
	if err := p.requestLog(e, true, nil); err != nil {
		t.Fatal(err)
	}
	out := Assessment{Heights: []Height{{Height: wideHeight}}}
	p.finishRequests(f.m, &out)
	if out.Sources.UnlocatedRequests != 1 || len(out.Heights[0].Requests) != 0 {
		t.Fatal(out)
	}
	p.count = MaxProcessingRecords
	e.Record.View = &event.View{Seq: wideHeight, Round: "0"}
	if err := p.requestLog(e, true, nil); err == nil {
		t.Fatal("request bypassed the combined source bound")
	}
}
