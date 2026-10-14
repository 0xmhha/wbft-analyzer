package scenario

import (
	"reflect"
	"testing"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

func TestApplicationRangeKeepsIncompleteRequestsWithinScope(t *testing.T) {
	mono := "0"
	req := func(height string, line int64) logs.Event {
		return logs.Event{Node: "a", Input: "events", Run: "r", Line: line, Profile: logs.EventProfile, Mono: &mono, Record: event.Record{Kind: event.BuildRequest, View: &event.View{Seq: height}, Fields: map[string]any{"wait_ms": "0"}}}
	}
	inside, tail := req("10", 1), req("13", 2)
	xs := []logs.Event{inside, tail, req("18446744073709551626", 3)}
	selected, scope, err := ScopeApplication(xs, 1, 10)
	if err != nil || scope.AppExcluded != 2 || scope.AppUnscoped != 0 || len(selected) != 1 || selected[0].Line != 1 {
		t.Fatal(selected, scope, err)
	}
	timing, err := FitAppTiming(selected)
	if err != nil || timing.Unproved != 1 {
		t.Fatal("in-scope pending request hidden", timing, err)
	}
	submitted := inside
	submitted.Line = 4
	submitted.Record = event.Record{Kind: event.ProposalSubmitted, Fields: map[string]any{"number": "10"}}
	xs = append(xs, submitted)
	selected, scope, err = ScopeApplication(xs, 1, 10)
	if err != nil || scope.AppExcluded != 2 {
		t.Fatal(scope, err)
	}
	timing, err = FitAppTiming(selected)
	if err != nil || len(timing.Build) != 1 || timing.Unproved != 0 || timing.Build[0].FromLine != 1 || timing.Build[0].ToLine != 4 {
		t.Fatal(timing, err)
	}
	unknown := req("", 5)
	unknown.Record.View = nil
	selected, scope, err = ScopeApplication([]logs.Event{unknown, req("010", 6)}, 1, 10)
	if err != nil || len(selected) != 2 || scope.AppUnscoped != 2 {
		t.Fatal("unresolved source height discarded", selected, scope, err)
	}
}

func TestLinkRangeDoesNotResolveAmbiguousWholeInputPairs(t *testing.T) {
	xs := []pairs.Pair{
		{ID: "in", Strength: "link", Height: "10", Status: "valid"},
		{ID: "out", Strength: "link", Height: "13", Status: "valid"},
		{ID: "wide", Strength: "link", Height: "18446744073709551626", Status: "valid"},
		{ID: "ambiguous", Strength: "link", Status: "ambiguous", SendCandidates: 2, Views: []pairs.View{{Height: "10"}, {Height: "13"}}},
		{ID: "unknown", Strength: "link", Status: "ambiguous"},
		{ID: "unknown_view", Strength: "link", Views: []pairs.View{{Height: "13"}, {Height: ""}}},
		{ID: "all_outside", Strength: "link", Views: []pairs.View{{Height: "13"}, {Height: "14"}}},
	}
	selected, scope, err := ScopeLinks(xs, 1, 10)
	if err != nil || scope.LinksExcluded != 3 || scope.LinksUnscoped != 2 || len(selected) != 4 {
		t.Fatal(selected, scope, err)
	}
	if !reflect.DeepEqual(selected[1], xs[3]) || selected[1].Status != "ambiguous" || selected[1].SendCandidates != 2 {
		t.Fatal("filter manufactured a unique pair", selected)
	}
	if _, _, err := ScopeLinks(xs, 10, 1); err == nil {
		t.Fatal("inverted range accepted")
	}
	if _, _, err := ScopeApplication(nil, 0, 10); err == nil {
		t.Fatal("genesis request range accepted")
	}
}
