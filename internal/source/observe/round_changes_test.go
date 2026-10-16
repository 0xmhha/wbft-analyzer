package observe

import (
	"encoding/json"
	"github.com/0xmhha/wbft/observe/participation"
	"slices"
	"strings"
	"testing"
	"time"
)

func roundChangeFixture() Archive {
	a := fixture()
	node := "0x1111111111111111111111111111111111111111"
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	next := at.Add(time.Second)
	rows := []participation.Record{{Height: a.From, Source: "local", Hash: "0x2222222222222222222222222222222222222222222222222222222222222222", Round: "1", Proposer: node, Rounds: []participation.Round{{Round: "0", Proposer: node, Outcome: "round_change", Entered: &at}, {Round: "1", Proposer: node, Outcome: "committed", Entered: &next, Cause: "timeout"}}, Validators: []participation.ValidatorRound{{Round: "0", Validator: node, Index: 0, InPrevCommitted: true}}}}
	a.Replies[1] = reply("wbft_participation", []string{a.From, a.To}, rows)
	a.Replies[2] = reply("wbft_participationSummary", []string{a.From, a.To}, participation.Summarize(rows))
	a.Replies = append(a.Replies, reply("wbft_roundChanges", []string{a.From, a.To}, []participation.RoundChange{{Height: a.From, Round: "0", Proposer: node, Cause: "timeout", Next: "1"}}))
	return a
}

func TestRoundChangeUnavailableDoesNotBecomeZero(t *testing.T) {
	for _, body := range []string{`{"jsonrpc":"2.0","id":1,"result":null}`, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"secret"}}`} {
		a := roundChangeFixture()
		a.Replies[5].Response = json.RawMessage(body)
		s, err := Normalize(a)
		if err != nil || s.RoundChanges == nil || s.RoundChanges.Status != "unavailable" || s.RoundChanges.ComputedCount == nil || *s.RoundChanges.ComputedCount != 1 || s.RoundChanges.ReportedCount != nil || s.RoundChanges.DifferentRows != nil || s.Calls[5].Status != "unavailable" {
			t.Fatal("unavailable claim became a count", s, err)
		}
		raw, _ := json.Marshal(s)
		if strings.Contains(string(raw), "secret") {
			t.Fatal("RPC error text retained")
		}
	}
	a := fixture()
	s, err := Normalize(a)
	if err != nil || s.RoundChanges != nil {
		t.Fatal("uncaptured legacy request fabricated", s, err)
	}
	a = roundChangeFixture()
	a.Replies[1].Response = json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":null}`)
	s, err = Normalize(a)
	if err != nil || s.RoundChanges.Status != "unavailable" || s.RoundChanges.ComputedCount != nil || s.RoundChanges.ReportedCount == nil || *s.RoundChanges.ReportedCount != 1 {
		t.Fatal("missing participation became computed zero", s, err)
	}
}

func TestRoundChangeDifferencesPreserveReportedClaims(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]participation.RoundChange) []participation.RoundChange
		fields []string
	}{
		{"empty", func(_ []participation.RoundChange) []participation.RoundChange { return []participation.RoundChange{} }, []string{"count"}},
		{"cause", func(rs []participation.RoundChange) []participation.RoundChange {
			rs[0].Cause = "f_plus_one"
			return rs
		}, []string{"cause"}},
		{"next", func(rs []participation.RoundChange) []participation.RoundChange { rs[0].Next = "2"; return rs }, []string{"next"}},
		{"proposer", func(rs []participation.RoundChange) []participation.RoundChange {
			rs[0].Proposer = "0x2222222222222222222222222222222222222222"
			return rs
		}, []string{"proposer"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := roundChangeFixture()
			var env struct {
				Result []participation.RoundChange `json:"result"`
			}
			if json.Unmarshal(a.Replies[5].Response, &env) != nil {
				t.Fatal("fixture")
			}
			reported := tc.change(env.Result)
			a.Replies[5] = reply("wbft_roundChanges", []string{a.From, a.To}, reported)
			s, err := Normalize(a)
			if err != nil || s.RoundChanges.Status != "different" || s.RoundChanges.DifferentRows == nil || *s.RoundChanges.DifferentRows != 1 || !slices.Equal(s.RoundChanges.DifferentFields, tc.fields) || s.Comparison.Status != "match" {
				t.Fatal(s, err)
			}
			want, _ := json.Marshal(reported)
			if string(s.Calls[5].Data) != string(want) {
				t.Fatal("reported claim replaced by computed values", string(s.Calls[5].Data), string(want))
			}
		})
	}
}

func TestRoundChangeClaimValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Archive)
	}{
		{"request scope", func(a *Archive) { a.Replies[5].Params = []string{"1", "1"} }},
		{"duplicate request", func(a *Archive) { a.Replies = append(a.Replies, a.Replies[5]) }},
		{"duplicate row", func(a *Archive) {
			r := participation.RoundChange{Height: a.From, Round: "0", Proposer: "0x1111111111111111111111111111111111111111"}
			a.Replies[5] = reply("wbft_roundChanges", []string{a.From, a.To}, []participation.RoundChange{r, r})
		}},
		{"outside height", func(a *Archive) {
			a.Replies[5] = reply("wbft_roundChanges", []string{a.From, a.To}, []participation.RoundChange{{Height: "1", Round: "0", Proposer: "0x1111111111111111111111111111111111111111"}})
		}},
		{"unsafe round", func(a *Archive) {
			a.Replies[5] = reply("wbft_roundChanges", []string{a.From, a.To}, []participation.RoundChange{{Height: a.From, Round: "01", Proposer: "0x1111111111111111111111111111111111111111"}})
		}},
		{"unknown cause", func(a *Archive) {
			a.Replies[5] = reply("wbft_roundChanges", []string{a.From, a.To}, []participation.RoundChange{{Height: a.From, Round: "0", Proposer: "0x1111111111111111111111111111111111111111", Cause: "secret"}})
		}},
		{"negative next", func(a *Archive) {
			a.Replies[5] = reply("wbft_roundChanges", []string{a.From, a.To}, []participation.RoundChange{{Height: a.From, Round: "0", Proposer: "0x1111111111111111111111111111111111111111", Next: "-1"}})
		}},
		{"metadata bound", func(a *Archive) {
			a.Replies[5] = reply("wbft_roundChanges", []string{a.From, a.To}, make([]participation.RoundChange, maxRoundChangeRows+1))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := roundChangeFixture()
			tc.change(&a)
			if _, err := Normalize(a); err == nil {
				t.Fatal("invalid round-change source accepted")
			}
		})
	}
}
func TestNativeRoundChangeClaimsRetainFullScope(t *testing.T) {
	a := roundChangeFixture()
	s, err := Normalize(a)
	if err != nil {
		t.Fatalf("valid native round-change claim rejected: %v", err)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var obj struct {
		RoundChanges *struct {
			Status        string `json:"status"`
			ComputedCount *int   `json:"computed_count"`
			ReportedCount *int   `json:"reported_count"`
		} `json:"round_changes"`
	}
	if json.Unmarshal(raw, &obj) != nil || obj.RoundChanges == nil || obj.RoundChanges.Status != "match" || obj.RoundChanges.ComputedCount == nil || obj.RoundChanges.ReportedCount == nil || *obj.RoundChanges.ComputedCount != 1 || *obj.RoundChanges.ReportedCount != 1 {
		t.Fatalf("round-change comparison missing: %s", raw)
	}
	if len(s.Calls) != 6 || s.Calls[5].Method != "wbft_roundChanges" || s.Calls[5].Params[0] != a.From || s.Calls[5].Status != "available" {
		t.Fatal("original round-change request or full height lost", s.Calls)
	}
}
