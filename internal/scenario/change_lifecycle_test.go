package scenario

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/event"
)

func lifecycleCommand(node int, at int64, action string) LifecycleCommand {
	return LifecycleCommand{Node: indexPointer(node), AtNS: &at, Action: action}
}

func lifecycleChange(policy string, from, to int64, commands ...LifecycleCommand) NetworkChange {
	return NetworkChange{Kind: "node_lifecycle", FromNS: from, ToNS: to, SchedulePolicy: policy, Lifecycle: commands}
}

func TestNodeLifecycleMergeAndExplicitReplacementPreserveCallerAndOtherNodes(t *testing.T) {
	sc := delayFixture(t)
	sc.Schedule = []sim.NodeEvent{
		{At: 5, Node: sc.Validators[0].Address(), Action: sim.ActionStop},
		{At: 6, Node: sc.Validators[0].Address(), Action: sim.ActionEngineStop},
		{At: 6, Node: sc.Validators[1].Address(), Action: sim.ActionStop},
		{At: 8, Node: sc.Validators[0].Address(), Action: sim.ActionRestart},
		{At: 9, Node: sc.Validators[1].Address(), Action: sim.ActionRestart},
	}
	before, _ := ExecutionHash(sc)
	merge := lifecycleChange("merge", 0, 20, lifecycleCommand(0, 10, "stop"), lifecycleCommand(0, 11, "restart"))
	merged, _, err := ApplyNetworkChange(sc, merge)
	if err != nil || len(merged.Schedule) != 7 {
		t.Fatal("merge lost original commands", err)
	}
	effect, err := NodeLifecycleEvidence(sc, merge)
	if err != nil || effect.Retained != 5 || len(effect.Removed) != 0 {
		t.Fatal(effect, err)
	}
	replace := lifecycleChange("replace_window", 5, 9, lifecycleCommand(0, 5, "stop"), lifecycleCommand(0, 9, "restart"))
	changed, _, err := ApplyNetworkChange(sc, replace)
	if err != nil || len(changed.Schedule) != 4 {
		t.Fatal("replacement scope", err)
	}
	effect, err = NodeLifecycleEvidence(sc, replace)
	if err != nil || len(effect.Removed) != 3 || effect.Retained != 2 || !effect.InitialStartsPreserved {
		t.Fatal(effect, err)
	}
	for _, removed := range effect.Removed {
		if removed.Node != 0 {
			t.Fatal("removed another node", removed)
		}
	}
	if changed.Schedule[1] != sc.Schedule[2] || changed.Schedule[2] != sc.Schedule[4] || !reflect.DeepEqual(sc.Nodes, changed.Nodes) {
		t.Fatal("other node or startup options changed")
	}
	changed.Schedule[0].Action = "caller-mutation"
	after, _ := ExecutionHash(sc)
	if before != after || sc.Schedule[0].Action != sim.ActionStop {
		t.Fatal("baseline schedule aliased or mutated")
	}
}

func TestNodeLifecycleCanonicalOrderAndEqualTimeSourcePolicy(t *testing.T) {
	c := lifecycleChange("merge", 0, 20, lifecycleCommand(1, 10, "stop"), lifecycleCommand(0, 5, "stop"))
	a, hash, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	c.Lifecycle[0], c.Lifecycle[1] = c.Lifecycle[1], c.Lifecycle[0]
	b, same, err := c.Canonical()
	if err != nil || !bytes.Equal(a, b) || hash != same {
		t.Fatal("command order changed hash", err)
	}
	normalized, err := c.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	*c.Lifecycle[0].AtNS = 19
	if *normalized.Lifecycle[0].AtNS != 5 {
		t.Fatal("caller command pointer alias")
	}
	sc := delayFixture(t)
	sc.Schedule = []sim.NodeEvent{{At: 5, Node: sc.Validators[0].Address(), Action: sim.ActionStop}}
	change := lifecycleChange("merge", 0, 20, lifecycleCommand(0, 5, "restart"))
	changed, _, err := ApplyNetworkChange(sc, change)
	if err != nil || changed.Schedule[0].Action != "stop" || changed.Schedule[1].Action != "restart" {
		t.Fatal("recorded-first tie policy lost", err)
	}
}

func TestNodeLifecycleRejectsAmbiguityUnknownCommandsAndImpossibleState(t *testing.T) {
	sc := delayFixture(t)
	sc.Nodes[0].StartAfter = 3
	for _, c := range []NetworkChange{
		lifecycleChange("merge", 0, 20, lifecycleCommand(0, 2, "stop")),
		lifecycleChange("merge", 0, 20, lifecycleCommand(0, 4, "restart")),
		lifecycleChange("merge", 0, 20, lifecycleCommand(0, 4, "stop"), lifecycleCommand(0, 5, "stop")),
		lifecycleChange("merge", 0, 20, lifecycleCommand(0, 4, "stop"), lifecycleCommand(0, 4, "restart")),
		lifecycleChange("merge", 0, 20, lifecycleCommand(4, 4, "stop")),
		lifecycleChange("merge", 0, 20, lifecycleCommand(0, 21, "stop")),
		lifecycleChange("merge", 0, 20, lifecycleCommand(0, 4, "crash")),
		lifecycleChange("merge", 0, 20, lifecycleCommand(0, 4, "engine_stop")),
		lifecycleChange("unknown", 0, 20, lifecycleCommand(0, 4, "stop")),
	} {
		if _, _, err := ApplyNetworkChange(sc, c); err == nil {
			t.Fatal("invalid lifecycle accepted", c)
		}
	}
	for _, raw := range []string{
		`{"kind":"node_lifecycle","from_ns":0,"to_ns":20,"schedule_policy":"merge","lifecycle":[{"node":0,"action":"stop"}]}`,
		`{"kind":"node_lifecycle","from_ns":0,"to_ns":20,"schedule_policy":"merge","lifecycle":[{"at_ns":0,"action":"stop"}]}`,
		`{"kind":"node_lifecycle","from_ns":0,"to_ns":20,"schedule_policy":"merge","lifecycle":[{"node":0,"at_ns":null,"action":"stop"}]}`,
		`{"kind":"node_lifecycle","from_ns":0,"to_ns":20,"schedule_policy":"merge","lifecycle":[{"node":0,"at_ns":0,"action":"stop","transaction":true}]}`,
		`{"kind":"node_lifecycle","from_ns":0,"to_ns":20,"schedule_policy":"merge","lifecycle":[{"Node":0,"at_ns":0,"action":"stop"}]}`,
		`{"kind":"node_lifecycle","from_ns":0,"to_ns":20,"schedule_policy":"merge","lifecycle":[],"edges":null}`,
		`{"kind":"cut_outgoing","from_ns":0,"to_ns":20,"node":0,"lifecycle":null}`,
	} {
		var c NetworkChange
		if json.Unmarshal([]byte(raw), &c) == nil {
			t.Fatal("missing, unknown or irrelevant field accepted", raw)
		}
	}
	boundary := lifecycleChange("merge", 0, int64(time.Minute), lifecycleCommand(0, 3, "stop"), lifecycleCommand(0, int64(time.Minute), "restart"))
	if _, _, err := ApplyNetworkChange(sc, boundary); err != nil {
		t.Fatal("inclusive initial-start or end boundary rejected", err)
	}
}

func TestNodeLifecycleUsesFullNodeStopAndPersistentRestartInsteadOfEngineOnly(t *testing.T) {
	sc := delayFixture(t)
	sc.Until = sim.Stop{Height: 12, Duration: time.Minute}
	sc.Seed = 7
	stop := lifecycleChange("merge", 0, int64(time.Minute), lifecycleCommand(3, int64(2*time.Second), "stop"))
	stopped, _, err := ApplyNetworkChange(sc, stop)
	if err != nil {
		t.Fatal(err)
	}
	full, err := sim.Run(context.Background(), stopped, sim.Output{})
	if err != nil || len(full.Violations) != 0 {
		t.Fatal("full stop", err, full.Violations)
	}
	engine := sc
	engine.Schedule = []sim.NodeEvent{{At: 2 * time.Second, Node: sc.Validators[3].Address(), Action: sim.ActionEngineStop}}
	only, err := sim.Run(context.Background(), engine, sim.Output{})
	if err != nil || len(only.Violations) != 0 {
		t.Fatal("engine stop", err, only.Violations)
	}
	if full.Heads[3] >= 12 || only.Heads[3] < 12 {
		t.Fatal("node stop treated as engine-only", full.Heads, only.Heads)
	}
	restart := lifecycleChange("merge", 0, int64(time.Minute), lifecycleCommand(3, int64(2*time.Second), "stop"), lifecycleCommand(3, int64(4*time.Second), "restart"))
	changed, _, err := ApplyNetworkChange(sc, restart)
	if err != nil {
		t.Fatal(err)
	}
	result, err := sim.Run(context.Background(), changed, sim.Output{})
	if err != nil || len(result.Violations) != 0 || result.Heads[3] < 12 {
		t.Fatal("restart lost persistent state", err, result.Heads, result.Violations)
	}
	starts := 0
	recovered := false
	for _, raw := range result.Events {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var record struct {
				Kind     event.Kind `json:"kind"`
				Node     string     `json:"node"`
				Mono     int64      `json:"t_mono_ns"`
				Recovery struct {
					Records int `json:"records"`
				} `json:"wal_recovery"`
			}
			if json.Unmarshal([]byte(line), &record) != nil {
				t.Fatal("event decode")
			}
			if record.Kind == event.NodeStart && strings.EqualFold(record.Node, sc.Validators[3].Address().Hex()) {
				starts++
				if record.Mono >= int64(4*time.Second) {
					recovered = record.Recovery.Records > 0
				}
			}
		}
	}
	// sign_floor is a takeover guard, not the ordinary last-sign state. The
	// official simulator reopens the signer on this same node filesystem.
	if starts != 2 || !recovered || !reflect.DeepEqual(changed.Nodes, sc.Nodes) {
		t.Fatal("same-node persistent restart lost", starts, recovered)
	}
}
