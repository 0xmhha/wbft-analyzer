package scenario

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
)

func TestSealingPolicyUsesExactDeclaredSamplesAndRejectsRestartConflicts(t *testing.T) {
	nodes, links := completeFixture()
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, []time.Duration{0}, []time.Duration{0}, sim.Stop{Height: 5, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for i := range sc.Nodes {
		sc.Nodes[i].BuildQueuePolicy = sim.BuildQueueSealing
		sc.Nodes[i].Sealing = &sim.SealingProfile{Selection: sim.SealingSeeded, ResultCapacity: i + 1, CallDelay: []time.Duration{0, time.Millisecond, 0}, PostDelay: []time.Duration{2 * time.Millisecond}}
		sc.Nodes[i].BuildDelay = []time.Duration{7 * time.Millisecond, 2 * time.Millisecond, 7 * time.Millisecond}
		sc.Nodes[i].ImportDelay = []time.Duration{3 * time.Millisecond, 4 * time.Millisecond}
	}
	result, err := sim.Run(context.Background(), sc, sim.Output{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Violations) > 0 {
		t.Fatal(result.Violations)
	}
	actualNodes := append([]Node(nil), nodes...)
	for i := range actualNodes {
		actualNodes[i].Address = sc.Validators[i].Address()
	}
	byNode := map[string][]byte{}
	for _, data := range result.Events {
		var first struct{ Node string }
		if err := json.Unmarshal(bytes.SplitN(data, []byte("\n"), 2)[0], &first); err != nil {
			t.Fatal(err)
		}
		byNode[first.Node] = data
	}
	policies := []ApplicationPolicy{}
	for _, n := range actualNodes {
		address := strings.ToLower(n.Address.Hex())
		data := byNode[address]
		sum := sha256.Sum256(data)
		in, err := InspectEvents(context.Background(), Input{ID: "events", Kind: "events", Node: address, SHA256: hex.EncodeToString(sum[:])}, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		observed := 0
		for _, row := range in.Records {
			if row.Record.Kind == "SIM_SEALING_STAGE" {
				if row.Record.Fields["actor"] == nil || row.Record.Fields["stage"] == nil || row.Line < 1 || row.Input != "events" {
					t.Fatal("lost actor source metadata", row)
				}
				observed++
			}
		}
		if observed == 0 {
			t.Fatal("no actor observations")
		}
		rows, err := FitApplicationPolicies(address, "events", in.Records)
		if err != nil || len(rows) != 1 {
			t.Fatal(rows, err)
		}
		if rows[0].Status != "declared_simulator" || rows[0].Sealing == nil || rows[0].Line != 1 || rows[0].Run == "" {
			t.Fatal(rows)
		}
		policies = append(policies, rows...)
	}
	neutral := sc
	neutral.Nodes = append([]sim.NodeSpec(nil), sc.Nodes...)
	for i := range neutral.Nodes {
		neutral.Nodes[i].BuildQueuePolicy = ""
		neutral.Nodes[i].Sealing = nil
		neutral.Nodes[i].BuildDelay = []time.Duration{99 * time.Millisecond}
		neutral.Nodes[i].ImportDelay = []time.Duration{99 * time.Millisecond}
	}
	fitted, err := ApplyApplicationPolicies(neutral, actualNodes, policies)
	if err != nil {
		t.Fatal(err)
	}
	for i := range fitted.Nodes {
		got, want := fitted.Nodes[i], sc.Nodes[i]
		if got.BuildQueuePolicy != want.BuildQueuePolicy || !reflect.DeepEqual(got.Sealing, want.Sealing) || !reflect.DeepEqual(got.BuildDelay, want.BuildDelay) || !reflect.DeepEqual(got.ImportDelay, want.ImportDelay) {
			t.Fatal("declared sampling replaced by measured successes", i, got, want)
		}
	}
	fitted.Nodes[0].Sealing.CallDelay[0] = 17
	if policies[0].Sealing.CallReturnDelayNS[0] != "0" || neutral.Nodes[0].Sealing != nil {
		t.Fatal("policy application mutated source")
	}
	for _, mode := range []string{"capacity", "order", "samples", "running_gate", "outside_duration"} {
		bad := append([]ApplicationPolicy(nil), policies...)
		next := bad[0]
		next.Run = "writer-two"
		next.Line = 91
		decl := *next.Sealing
		next.Sealing = &decl
		switch mode {
		case "capacity":
			decl.ResultCapacity++
		case "order":
			decl.AssemblyDelayNS = []string{"2000000", "7000000", "7000000"}
		case "samples":
			decl.CallReturnDelayNS = []string{"0", "1000000"}
		case "running_gate":
			decl.RunningGate = "at_return"
		case "outside_duration":
			decl.ImportDelayNS = []string{"9223372036854775807"}
			bad[0] = next
		}
		if mode != "outside_duration" {
			bad = append(bad, next)
		}
		if _, err := ApplyApplicationPolicies(neutral, actualNodes, bad); err == nil {
			t.Fatal("conflicting/unbounded declaration accepted", mode)
		}
	}
}
