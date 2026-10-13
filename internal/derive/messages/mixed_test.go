package messages

import "testing"

func TestMixedWeakestSideAndBoundary(t *testing.T) {
	a := endpoint("send", "a", "b", "1", "bytes", 0)
	b := endpoint("receive", "a", "b", "1", "bytes", 1)
	a.Source.Kind = "message"
	a.Author = "a"
	b.Source.Kind = "event"
	b.Strength = "node"
	p := PairEndpoints(MixEndpoints([]Endpoint{a, b}), Clock{Model: "shared-host"})
	if len(p) != 1 || p[0].Strength != "node" || p[0].Metric != "propagation_processing" || p[0].Status != "valid" {
		t.Fatal(p)
	}
	b.Strength = "key"
	b.Key = ""
	b.Digest = ""
	a.Digest = "known"
	p = PairEndpoints(MixEndpoints([]Endpoint{a, b}), Clock{Model: "shared-host"})
	if len(p) != 1 || p[0].Strength != "key" || p[0].Status != "valid" {
		t.Fatal(p)
	}
	b.Strength = "link"
	b.Key = a.Key
	b.Source.Kind = "message"
	a.Strength = "node"
	p = PairEndpoints(MixEndpoints([]Endpoint{a, b}), Clock{Model: "shared-host"})
	if p[0].Strength != "node" || p[0].Metric != "broadcast_to_receipt" {
		t.Fatal(p)
	}
}
func TestAlternateGradeDoesNotDuplicatePairAndRetriesRemainAmbiguous(t *testing.T) {
	a := endpoint("send", "a", "b", "1", "bytes", 0)
	b := endpoint("receive", "a", "b", "1", "bytes", 1)
	c, d := a, b
	c.Strength = "node"
	d.Strength = "node"
	c.Source.Input = "event-a"
	d.Source.Input = "event-b"
	p := PairEndpoints(MixEndpoints([]Endpoint{a, b, c, d}), Clock{Model: "shared-host"})
	if len(p) != 1 || p[0].Strength != "link" || p[0].SendCandidates != 1 {
		t.Fatal(p)
	}
	p = PairEndpoints(MixEndpoints([]Endpoint{a, b, a, c, d}), Clock{Model: "shared-host"})
	if len(p) != 1 || p[0].Status != "ambiguous" || p[0].SendCandidates != 2 {
		t.Fatal(p)
	}
	a.Height = "18446744073709551617"
	a.Author = "a"
	b.Strength = "key"
	b.Key = ""
	p = PairEndpoints(MixEndpoints([]Endpoint{a, b}), Clock{Model: "shared-host"})
	if len(p) != 1 || p[0].Status != "ambiguous" {
		t.Fatal("mixed low64 collision paired", p)
	}
}

func TestWeakScopeDoesNotMergeUnrelatedByteIdentities(t *testing.T) {
	a := endpoint("send", "a", "b", "1", "first", 0)
	b := endpoint("receive", "a", "b", "1", "first", 1)
	c, d := a, b
	c.Key = "second"
	d.Key = "second"
	w := endpoint("receive", "a", "b", "2", "", 1)
	w.Strength = "key"
	p := PairEndpoints(MixEndpoints([]Endpoint{a, b, c, d, w}), Clock{Model: "shared-host"})
	valid := 0
	for _, x := range p {
		if x.Status == "valid" && x.Strength == "link" {
			valid++
		}
	}
	if valid != 2 {
		t.Fatal("unrelated weak view erased strong identities", p)
	}
}

func TestRelayCannotBecomeWeakOrigin(t *testing.T) {
	a := endpoint("send", "relay", "receiver", "1", "bytes", 0)
	a.Source.Kind = "message"
	a.Author = "origin"
	a.Cause = "relay"
	b := endpoint("receive", "relay", "receiver", "1", "", 1)
	b.Strength = "key"
	projection := MixProjection([]Endpoint{a, b})
	p := PairEndpoints(projection.Endpoints, Clock{Model: "shared-host"})
	if projection.Counts["relay_origin_unresolved"] != 1 || len(p) != 1 || p[0].Status != "missing_send" || p[0].Seconds != nil {
		t.Fatal(projection, p)
	}
}

func TestGradeSelectionCannotHideContradictoryWeakCandidate(t *testing.T) {
	send := endpoint("send", "a", "b", "1", "", 0)
	send.Strength = "key"
	receive := endpoint("receive", "a", "b", "1", "wire", 1)
	alternate := receive
	alternate.Strength = "node"
	alternate.Key = "different-bytes"
	alternate.Source.Input = "alternate"
	pairs := PairEndpoints(MixEndpoints([]Endpoint{send, receive, alternate}), Clock{Model: "shared-host"})
	if len(pairs) != 1 || pairs[0].Status != "ambiguous" || pairs[0].ReceiveCandidates != 2 {
		t.Fatal("grade selection hid a different possible identity", pairs)
	}
}
