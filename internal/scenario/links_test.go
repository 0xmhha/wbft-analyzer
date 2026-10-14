package scenario

import (
	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"testing"
	"time"
)

func TestLinkFitRequiresReceiptAndCoverageEvidence(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pair := func(id, status string) *pairs.Pair {
		return &pairs.Pair{ID: id, Sender: "a", Receiver: "b", Strength: "link", Status: status, SendCandidates: 1, Write: "ok", Send: &pairs.Source{Node: "a", Wall: at.Add(time.Second).Format(time.RFC3339Nano)}}
	}
	valid := pair("one", "valid")
	valid.ReceiveCandidates = 1
	valid.Receive = &pairs.Source{Node: "b", Wall: at.Add(time.Second + 10*time.Millisecond).Format(time.RFC3339Nano)}
	missing := pair("two", "missing_receive")
	xs := []pairs.Pair{*valid, *missing}
	for _, clock := range []string{"unknown", "shared-host", "ntp"} {
		got, err := FitLinks([]string{"a", "b"}, xs, nil, clock, time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if got[0].Loss != nil || got[0].Status == "complete" {
			t.Fatalf("uncovered %s: %+v", clock, got[0])
		}
	}
	coverage := []Coverage{{Node: "b", From: at, To: at.Add(3 * time.Second), SettledThrough: at.Add(2 * time.Second), Complete: true}}
	got, err := FitLinks([]string{"a", "b"}, xs, coverage, "ntp", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	l := got[0]
	if l.Status != "complete" || l.Loss == nil || *l.Loss != 0.5 || l.Delays[0].Lower != 9000000 || l.Delays[0].Upper != 11000000 {
		t.Fatalf("fit: %+v", l)
	}
	if got[1].Status != "unavailable" || got[1].Loss != nil {
		t.Fatal("invented reverse link")
	}
	coverage[0].SettledThrough = at.Add(time.Second)
	got, err = FitLinks([]string{"a", "b"}, xs, coverage, "shared-host", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Loss != nil {
		t.Fatal("unsettled tail counted as loss")
	}
}

func TestLinkFitExcludesAmbiguousWeakAndFailedWrites(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	base := pairs.Pair{ID: "base", Sender: "a", Receiver: "b", Strength: "link", Status: "valid", SendCandidates: 1, ReceiveCandidates: 1, Write: "ok", Send: &pairs.Source{Node: "a", Wall: at}, Receive: &pairs.Source{Node: "b", Wall: at}}
	for _, alter := range []func(*pairs.Pair){func(p *pairs.Pair) { p.Strength = "node" }, func(p *pairs.Pair) { p.Status = "ambiguous"; p.ReceiveCandidates = 2 }, func(p *pairs.Pair) { p.Write = "failed" }} {
		p := base
		alter(&p)
		got, err := FitLinks([]string{"a", "b"}, []pairs.Pair{p}, nil, "shared-host", 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(got[0].Delays) > 0 || got[0].Loss != nil {
			t.Fatal("invented link evidence")
		}
	}
	if _, err := FitLinks([]string{"a", "b"}, []pairs.Pair{base, base}, nil, "shared-host", 0); err == nil {
		t.Fatal("duplicate pair accepted")
	}
}

func TestObservedPairAloneDoesNotProveLoss(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	p := pairs.Pair{ID: "one", Sender: "a", Receiver: "b", Strength: "link", Status: "valid", SendCandidates: 1, ReceiveCandidates: 1, Write: "ok", Send: &pairs.Source{Node: "a", Wall: at}, Receive: &pairs.Source{Node: "b", Wall: at}}
	links, err := FitLinks([]string{"a", "b"}, []pairs.Pair{p}, nil, "shared-host", 0)
	if err != nil {
		t.Fatal(err)
	}
	if links[0].Loss != nil || links[0].Status != "partial" {
		t.Fatal("receipt manufactured complete receiver scope")
	}
}

func TestReceiverCoverageMustContainObservedSend(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := pairs.Pair{ID: "outside", Sender: "a", Receiver: "b", Strength: "link", Status: "valid", SendCandidates: 1, ReceiveCandidates: 1, Write: "ok", Send: &pairs.Source{Node: "a", Wall: at.Add(10 * time.Second).Format(time.RFC3339Nano)}, Receive: &pairs.Source{Node: "b", Wall: at.Add(11 * time.Second).Format(time.RFC3339Nano)}}
	c := []Coverage{{Node: "b", From: at, To: at.Add(3 * time.Second), SettledThrough: at.Add(2 * time.Second), Complete: true}}
	got, err := FitLinks([]string{"a", "b"}, []pairs.Pair{p}, c, "shared-host", 0)
	if err != nil || got[0].Loss != nil || got[0].Status != "partial" || len(got[0].Delays) != 1 {
		t.Fatal("unrelated coverage proved loss", err)
	}
}
