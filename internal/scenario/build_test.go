package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

func completeFixture() ([]Node, []Link) {
	nodes := []Node{}
	for i := 1; i <= 4; i++ {
		nodes = append(nodes, Node{Address: types.Address{19: byte(i)}, Profile: "compat", ReplayWAL: true, RuntimeEvidence: "verified", Improvements: uint64(consensus.RestartSafety)})
	}
	links := []Link{}
	loss := 0.0
	for _, a := range nodes {
		for _, b := range nodes {
			if a.Address != b.Address {
				links = append(links, Link{Sender: a.Address.Hex(), Receiver: b.Address.Hex(), Status: "complete", Loss: &loss, Delays: []Delay{{Nanoseconds: 1000000, Lower: 1000000, Upper: 1000000}}})
			}
		}
	}
	return nodes, links
}

func TestBuildRequiresCompleteDirectedModels(t *testing.T) {
	nodes, links := completeFixture()
	params := sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 10}
	stop := sim.Stop{Height: 3, Duration: time.Minute}
	delay := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, params, delay, delay, stop)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.Links) != 12 || len(sc.Nodes) != 4 {
		t.Fatal("missing model")
	}
	if err := RunSeeds(context.Background(), sc, []int64{1}, 1, 3, func(r SeedResult) error {
		if r.Status != "complete" {
			t.Fatalf("baseline %+v", r)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]Link{links[:11], append(append([]Link{}, links[:11]...), links[0])} {
		if _, err := Build(nodes, bad, params, delay, delay, stop); err == nil {
			t.Fatal("missing or duplicate directed link accepted")
		}
	}
	links[0].Loss = nil
	if _, err := Build(nodes, links, params, delay, delay, stop); err == nil {
		t.Fatal("unknown loss defaulted to zero")
	}
	_, links = completeFixture()
	links[0].Status = "partial"
	if _, err := Build(nodes, links, params, delay, delay, stop); err == nil {
		t.Fatal("partial evidence accepted")
	}
	_, links = completeFixture()
	if _, err := Build(nodes, links, params, nil, delay, stop); err == nil {
		t.Fatal("defaulted missing build delay")
	}

	nodes[0].RuntimeEvidence = ""
	if _, err := Build(nodes, links, params, delay, delay, stop); err == nil {
		t.Fatal("runtime evidence inferred from core options")
	}
	nodes[0].RuntimeEvidence = "verified"
	floor := "1"
	nodes[0].SignFloor = &floor
	if _, err := Build(nodes, links, params, delay, delay, stop); err == nil {
		t.Fatal("recorded sign floor silently ignored")
	}
}
