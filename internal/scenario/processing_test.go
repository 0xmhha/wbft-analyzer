package scenario

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus/inputlog"
)

func syntheticProcessingTimings(o FitOptions) []ProcessingTimings {
	rows := []ProcessingTimings{}
	for _, p := range o.Journals {
		source := Input{ID: p.Summary.ID, Kind: p.Summary.Kind, Node: p.Summary.Node, SHA256: p.Summary.SHA256}
		timing := ProcessingTimings{Source: source, Status: "complete", Scope: "recorded_core_head_plus_one", From: o.From, To: o.To, Samples: []ProcessingSample{}, Excluded: []ProcessingExcluded{}, Assumptions: []string{"synthetic_test_intervals"}}
		for i, d := range []int64{1000000, 1000000, 3000000} {
			end := "1000000"
			if d == 3000000 {
				end = "3000000"
			}
			timing.Samples = append(timing.Samples, ProcessingSample{Point: ProcessingPoint{Ordinal: int64(i + 2), File: "00000000000000000000.wal", Run: "synthetic", Engine: "1", Step: strconv.Itoa(i + 2), Height: "2"}, Kind: inputlog.KindRequest, EntryMono: "0", CompleteMono: end, Nanoseconds: d})
		}
		rows = append(rows, timing)
	}
	return rows
}

func TestProcessingEvidenceBindsModelAndExecutionWithExactSamples(t *testing.T) {
	o := empiricalFitFixture(t)
	zero, err := Fit(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	o.ProcessingPolicy, o.ProcessingWorkers = NativeProcessingPolicy, 1
	o.ProcessingTimings = syntheticProcessingTimings(o)
	fitted, err := Fit(context.Background(), o)
	if err != nil || fitted.Model.Status != "complete" || fitted.Scenario == nil || fitted.Model.Processing == nil || fitted.SourceSHA256 == zero.SourceSHA256 {
		t.Fatal("processing evidence not bound to fitting", fitted.Model, err)
	}
	want := []time.Duration{time.Millisecond, time.Millisecond, 3 * time.Millisecond}
	for _, node := range fitted.Scenario.Nodes {
		if node.Processing == nil || node.Processing.Workers != 1 || !reflect.DeepEqual(node.Processing.Costs[0].Samples, want) {
			t.Fatal("sample order or multiplicity changed", node.Processing)
		}
	}
	zeroHash, _ := ExecutionHash(*zero.Scenario)
	firstHash, _ := ExecutionHash(*fitted.Scenario)
	if zeroHash == firstHash || strings.Contains(strings.Join(fitted.Provenance.Assumptions, " "), "receive_checks_and_core_steps_consume_no_simulated_time") {
		t.Fatal("processing was not executable or kept a false zero-cost assumption")
	}
	o.ProcessingWorkers = 2
	changed, err := Fit(context.Background(), o)
	if err != nil || changed.Scenario == nil {
		t.Fatal(changed.Model, err)
	}
	changedHash, _ := ExecutionHash(*changed.Scenario)
	if changedHash == firstHash || changed.SourceSHA256 == fitted.SourceSHA256 {
		t.Fatal("worker count escaped source or execution identity")
	}
	o.ProcessingTimings[0].Samples[0].Nanoseconds++
	o.ProcessingTimings[0].Assumptions[0] = "changed_caller_metadata"
	if fitted.Model.Processing.Timings[0].Samples[0].Nanoseconds != 1000000 || fitted.Model.Processing.Timings[0].Assumptions[0] != "synthetic_test_intervals" || fitted.Scenario.Nodes[0].Processing.Costs[0].Samples[0] != time.Millisecond {
		t.Fatal("fitted evidence or executable costs alias caller memory")
	}
}

func TestProcessingEvidencePreservesMissingMeasurementGate(t *testing.T) {
	o := empiricalFitFixture(t)
	o.ProcessingPolicy, o.ProcessingWorkers = NativeProcessingPolicy, 1
	o.ProcessingTimings = syntheticProcessingTimings(o)
	o.ProcessingTimings = o.ProcessingTimings[:len(o.ProcessingTimings)-1]
	got, err := Fit(context.Background(), o)
	if err != nil || got.Model.Status != "partial" || got.Scenario != nil || got.Model.Processing == nil {
		t.Fatal("missing native timing source was defaulted", got.Model, err)
	}
	o.ProcessingTimings = syntheticProcessingTimings(o)
	o.ProcessingTimings[0].Samples[0].Nanoseconds++
	if _, err := Fit(context.Background(), o); err == nil {
		t.Fatal("duration disagreed with measured endpoints")
	}
}
