package messages

import (
	"testing"
	"time"
)

func endpoint(role, sender, receiver, height, key string, ns int) Endpoint {
	wall := "2020-01-01T00:00:00Z"
	if ns != 0 {
		wall = "2020-01-01T00:00:00.010Z"
	}
	return Endpoint{Source: Source{Input: role, Ordinal: 1, Node: sender, Run: "run", Wall: wall}, Role: role, Strength: "link", Sender: sender, Receiver: receiver, Phase: "PREPARE", Height: height, Round: "0", Key: key, Write: "ok"}
}
func TestDirectionDuplicatesAndWeakCollision(t *testing.T) {
	a := endpoint("send", "a", "b", "1", "key", 0)
	b := endpoint("receive", "a", "b", "1", "key", 1)
	c := endpoint("send", "b", "a", "1", "key", 0)
	d := endpoint("receive", "b", "a", "1", "key", 1)
	p := PairEndpoints([]Endpoint{a, b, c, d}, Clock{Model: "shared-host"})
	if len(p) != 2 || p[0].Sender == p[1].Sender || p[0].Status != "valid" || *p[0].Seconds != .01 {
		t.Fatal(p)
	}
	p = PairEndpoints([]Endpoint{a, b, a}, Clock{Model: "shared-host"})
	if len(p) != 1 || p[0].Status != "ambiguous" || p[0].Seconds != nil {
		t.Fatal(p)
	}
	a.Strength = "key"
	b.Strength = "key"
	b.Height = "18446744073709551617"
	p = PairEndpoints([]Endpoint{a, b}, Clock{Model: "shared-host"})
	if len(p) != 1 || p[0].Status != "ambiguous" {
		t.Fatal("low64 collision paired", p)
	}
}
func TestClockUncertaintyAndWriteEvidence(t *testing.T) {
	a := endpoint("send", "a", "b", "1", "key", 0)
	b := endpoint("receive", "a", "b", "1", "key", 1)
	p := PairEndpoints([]Endpoint{a, b}, Clock{Model: "unknown"})[0]
	if p.Status != "unknown_clock" || p.Seconds != nil || p.RawSeconds == nil {
		t.Fatal(p)
	}
	p = PairEndpoints([]Endpoint{a, b}, Clock{Model: "ntp", SkewMS: 20})[0]
	if p.Status != "clock_overlap" || p.Seconds != nil || *p.Lower != -.01 || *p.Upper != .03 {
		t.Fatal(p)
	}
	a.Source.Wall, b.Source.Wall = b.Source.Wall, a.Source.Wall
	p = PairEndpoints([]Endpoint{a, b}, Clock{Model: "shared-host"})[0]
	if p.Status != "negative" || p.Seconds != nil {
		t.Fatal(p)
	}
	a.Write = "error"
	p = PairEndpoints([]Endpoint{a, b}, Clock{Model: "shared-host"})[0]
	if p.Status != "unconfirmed_write" {
		t.Fatal(p)
	}
}

func TestWeakDoubleSigningIsNotSeparatedIntoPlausiblePairs(t *testing.T) {
	a := endpoint("send", "a", "b", "1", "", 0)
	b := endpoint("receive", "a", "b", "1", "", 1)
	a.Strength = "key"
	b.Strength = "key"
	a.Digest = "x"
	b.Digest = "x"
	c, d := a, b
	c.Digest = "y"
	d.Digest = "y"
	ps := PairEndpoints([]Endpoint{a, b, c, d}, Clock{Model: "shared-host"})
	for _, p := range ps {
		if p.Status != "ambiguous" || p.Seconds != nil {
			t.Fatal(p)
		}
	}
}

func TestLocalClockCannotCrossRunsOrFallBackToWall(t *testing.T) {
	a := endpoint("send", "a", "a", "1", "key", 0)
	b := endpoint("receive", "a", "a", "1", "key", 1)
	lo, hi := "1", "11"
	a.Source.Mono = &lo
	b.Source.Mono = &hi
	p := PairEndpoints([]Endpoint{a, b}, Clock{Model: "unknown"})[0]
	if p.Status != "valid" || p.Clock != "monotonic" || p.Path != "local" || *p.Seconds != 1e-8 {
		t.Fatal(p)
	}
	b.Source.Run = "restart"
	p = PairEndpoints([]Endpoint{a, b}, Clock{Model: "shared-host"})[0]
	if p.Status != "missing_clock" || p.Seconds != nil {
		t.Fatal(p)
	}
	b.Source.Run = a.Source.Run
	b.Source.Mono = nil
	p = PairEndpoints([]Endpoint{a, b}, Clock{Model: "shared-host"})[0]
	if p.Status != "missing_clock" {
		t.Fatal(p)
	}
	bad := "18446744073709551617"
	b.Source.Mono = &bad
	p = PairEndpoints([]Endpoint{a, b}, Clock{Model: "shared-host"})[0]
	if p.Status != "invalid_clock" {
		t.Fatal(p)
	}
}

func TestWallNanosecondsAndNonSaturatingInterval(t *testing.T) {
	a := endpoint("send", "a", "b", "1", "bytes", 0)
	b := endpoint("receive", "a", "b", "1", "bytes", 1)
	a.Source.Wall = "2020-01-01T00:00:00.000000001Z"
	b.Source.Wall = "2020-01-01T00:00:00.000000002Z"
	p := PairEndpoints([]Endpoint{a, b}, Clock{Model: "shared-host"})[0]
	if p.Status != "valid" || *p.Seconds != 1e-9 {
		t.Fatal(p)
	}
	a.Source.Wall = "1700-01-01T00:00:00Z"
	b.Source.Wall = "2200-01-01T00:00:00Z"
	x, _ := time.Parse(time.RFC3339Nano, a.Source.Wall)
	y, _ := time.Parse(time.RFC3339Nano, b.Source.Wall)
	p = PairEndpoints([]Endpoint{a, b}, Clock{Model: "shared-host"})[0]
	if p.Status != "valid" || *p.Seconds != float64(y.Unix()-x.Unix()) {
		t.Fatal("duration saturated", p)
	}
}
