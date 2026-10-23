package scenario

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestRecordedReceiveLanePreservesExplicitLimits(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		nodes, links := completeFixture()
		address := nodes[0].Address
		options := journal.CoreOptions{Self: address, ChainConfig: []byte(`{"chainId":7,"anzeon":{"wbft":{"epochLength":10}}}`), Profile: "compat", Improvements: uint64(consensus.RestartSafety)}
		if enabled {
			options.NextHeight = &journal.DeferredOptions{Profile: journal.DeferredInputProfile, Entries: 9007199254740993, Bytes: 1 << 20, PerPeer: 4, PerSource: 3}
		}
		if _, err := options.Configuration(); err != nil {
			t.Fatal("valid recorded configuration rejected", err)
		}
		dir := t.TempDir()
		writer, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Self: address, Run: "normal-receive-profile", Core: options})
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		node, _, err := InspectNodeOptions(t.Context(), dir, address)
		if err != nil {
			t.Fatal(err)
		}
		if (node.NextHeight != nil) != enabled {
			t.Fatal("recorded receive profile lost")
		}
		if enabled && (node.NextHeight.Version != "1" || node.NextHeight.Entries != "9007199254740993") {
			t.Fatal("source quota lost precision")
		}
		// The runtime binding is a declared test fixture, separate from the journal.
		node.ReplayWAL = true
		node.RuntimeEvidence = "verified"
		nodes[0] = node
		sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 10}, []time.Duration{time.Millisecond}, []time.Duration{time.Millisecond}, sim.Stop{Height: 2, Duration: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		limits := sc.Nodes[0].NextHeight
		if (limits != nil) != enabled {
			t.Fatal("simulator receiver configuration lost")
		}
		if enabled && (limits.Entries != 9007199254740993 || limits.Bytes != 1<<20 || limits.PerPeer != 4 || limits.PerSource != 3) {
			t.Fatal("modeled receive limits changed")
		}
		if _, err := sim.Run(t.Context(), sc, sim.Output{}); err != nil {
			t.Fatal(err)
		}
	}
}
