package scenario

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/event"
)

func declaredApplicationPolicy(node, run string, line int64) ApplicationPolicy {
	return ApplicationPolicy{Node: node, Input: "events", Run: run, Line: line, Status: "declared_simulator", BuildQueue: "serial-latest", DoneResult: "failed", AssemblyReturn: "sampled", Selection: "callbacks_then_done_then_pending"}
}
func TestApplicationPolicyKeepsStartupSourcesAndRequiresEveryDeclaration(t *testing.T) {
	n, links := completeFixture()
	rows := []logs.Event{}
	for _, r := range []string{"one", "two"} {
		rows = append(rows, logs.Event{Node: n[0].Address.Hex(), Input: "events", Run: r, Line: int64(len(rows) + 1), Profile: logs.EventProfile, Record: event.Record{Kind: event.NodeStart, Fields: map[string]any{"application_build_queue": "serial-latest", "application_done_result": "failed", "application_assembly_return": "sampled", "application_selection": "callbacks_then_done_then_pending"}}})
	}
	p, e := FitApplicationPolicies(n[0].Address.Hex(), "events", rows)
	if e != nil || len(p) != 2 || p[1].Line != 2 || p[1].Run != "two" {
		t.Fatal(p, e)
	}
	if _, ok := nodeApplicationPolicy(n[0].Address.Hex(), p); !ok {
		t.Fatal(p)
	}
	delete(rows[1].Record.Fields, "application_done_result")
	missing, e := FitApplicationPolicies(n[0].Address.Hex(), "events", rows)
	if e != nil || missing[1].Status != "unavailable" {
		t.Fatal(missing, e)
	}
	if _, ok := nodeApplicationPolicy(n[0].Address.Hex(), missing); ok {
		t.Fatal("first startup concealed missing declaration")
	}
	if _, e = FitApplicationPolicies("other", "events", rows); e == nil {
		t.Fatal("cross-node declaration accepted")
	}
	sc, e := Build(n, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, []time.Duration{0}, []time.Duration{0}, sim.Stop{Height: 3, Duration: time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	all := []ApplicationPolicy{}
	for _, node := range n {
		all = append(all, declaredApplicationPolicy(node.Address.Hex(), "one", 1))
	}
	all[1].DoneResult = "submitted"
	fitted, e := ApplyApplicationPolicies(sc, n, all)
	if e != nil || fitted.Nodes[0].BuildQueuePolicy != "serial-latest" || fitted.Nodes[1].BuildDoneResult != "submitted" || sc.Nodes[0].BuildQueuePolicy != "" {
		t.Fatal(fitted, e)
	}
	for _, mode := range []string{"missing", "duplicate", "conflict", "unknown", "outside"} {
		t.Run(mode, func(t *testing.T) {
			bad := append([]ApplicationPolicy(nil), all...)
			switch mode {
			case "missing":
				bad = bad[:len(bad)-1]
			case "duplicate":
				bad = append(bad, bad[0])
			case "conflict":
				next := bad[0]
				next.Run = "two"
				next.Line = 2
				next.DoneResult = "submitted"
				bad = append(bad, next)
			case "unknown":
				bad[0].Selection = "unrecorded"
			case "outside":
				bad = append(bad, declaredApplicationPolicy("other", "one", 1))
			}
			if _, e := ApplyApplicationPolicies(sc, n, bad); e == nil {
				t.Fatal("incomplete policy accepted", mode)
			}
		})
	}
}
func TestMissingApplicationPolicyKeepsMeasuredSuccessPartial(t *testing.T) {
	nodes, links := completeFixture()
	runtime := []Runtime{}
	app := AppTiming{}
	for _, n := range nodes {
		runtime = append(runtime, Runtime{Node: n.Address.Hex(), Starts: 1, SignFloorState: "none"})
		app.Build = append(app.Build, AppSample{Node: n.Address.Hex(), Nanoseconds: 1})
		app.Import = append(app.Import, AppSample{Node: n.Address.Hex(), Nanoseconds: 1})
	}
	got, e := Assess(nodes, links, runtime, app)
	if e != nil || got.Status != "partial" || len(got.Issues) != len(nodes) {
		t.Fatal(got, e)
	}
	for _, i := range got.Issues {
		if i.Code != "application_policy_unavailable" {
			t.Fatal(i)
		}
	}
}

func TestRecordedSerialSimulationRetainsDeclaredPerNodePolicies(t *testing.T) {
	nodes, links := completeFixture()
	sc, e := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, []time.Duration{time.Millisecond}, []time.Duration{time.Millisecond}, sim.Stop{Height: 3, Duration: time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	for i := range sc.Nodes {
		sc.Nodes[i].BuildQueuePolicy = "serial-latest"
		sc.Nodes[i].BuildDoneResult = "failed"
	}
	sc.Nodes[1].BuildDoneResult = "submitted"
	dir := t.TempDir()
	result, e := sim.Run(context.Background(), sc, sim.Output{EventsDir: dir})
	if e != nil {
		t.Fatal(e)
	}
	all := []ApplicationPolicy{}
	actualNodes := append([]Node(nil), nodes...)
	for i := range actualNodes {
		actualNodes[i].Address = sc.Validators[i].Address()
	}
	byNode := map[string][]byte{}
	for _, data := range result.Events {
		var first struct{ Node string }
		if e := json.Unmarshal(bytes.SplitN(data, []byte("\n"), 2)[0], &first); e != nil {
			t.Fatal(e)
		}
		byNode[first.Node] = data
	}
	for i, node := range actualNodes {
		address := strings.ToLower(node.Address.Hex())
		data := byNode[address]
		if len(data) == 0 {
			t.Fatal("recorded node events unavailable")
		}
		sum := sha256.Sum256(data)
		in, e := InspectEvents(context.Background(), Input{ID: "events", Kind: "events", Node: address, SHA256: hex.EncodeToString(sum[:])}, bytes.NewReader(data))
		if e != nil {
			t.Fatal(e)
		}
		policies, e := FitApplicationPolicies(address, "events", in.Records)
		if e != nil || len(policies) != 1 || policies[0].Status != "declared_simulator" || policies[0].DoneResult != sc.Nodes[i].BuildDoneResult {
			t.Fatal(policies, e)
		}
		all = append(all, policies...)
	}
	fitted, e := ApplyApplicationPolicies(sc, actualNodes, all)
	if e != nil || fitted.Nodes[1].BuildDoneResult != "submitted" || fitted.Nodes[0].BuildDoneResult != "failed" {
		t.Fatal(fitted, e)
	}
}
