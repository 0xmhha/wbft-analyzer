package scenario

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
)

// empiricalFixture reparses synthetic source bytes, including full-width IDs.
func empiricalFixture(t *testing.T, cancel bool) RuntimeObservation {
	t.Helper()
	raw, err := os.ReadFile("../source/runtimeobs/testdata/core-synthetic.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.ReplaceAll(raw, []byte("18446744073709551616"), []byte("2"))
	if cancel {
		raw = bytes.ReplaceAll(raw, []byte("seal_result"), []byte("seal_cancel"))
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	last := lines[len(lines)-1]
	lines = lines[:len(lines)-1]
	for _, spec := range []struct {
		id, operation, result, height string
		count, index                  int
	}{
		{"51", "write_block_and_set_head", "ok", "2", 1, 0},
		{"52", "insert_chain", "ok", "2", 1, 1},
		{"53", "insert_chain", "ok", "2", 2, 2},
		{"54", "write_block_and_set_head", "error", "2", 1, 0},
		{"55", "write_block_and_set_head", "ok", "18446744073709551616", 1, 0},
	} {
		for _, end := range []bool{false, true} {
			point := map[string]json.RawMessage{}
			if err := json.Unmarshal(lines[1], &point); err != nil {
				t.Fatal(err)
			}
			point["id"] = json.RawMessage(spec.id)
			point["height"], _ = json.Marshal(spec.height)
			if end {
				point["type"] = json.RawMessage(`"operation_end"`)
				point["result"], _ = json.Marshal(spec.result)
				point["index"] = json.RawMessage(strconv.Itoa(spec.index))
				delete(point, "operation")
				delete(point, "count")
			} else {
				point["operation"], _ = json.Marshal(spec.operation)
				point["count"] = json.RawMessage(strconv.Itoa(spec.count))
			}
			line, err := json.Marshal(point)
			if err != nil {
				t.Fatal(err)
			}
			lines = append(lines, line)
		}
	}
	lines = append(lines, last)
	var buf bytes.Buffer
	for i, line := range lines {
		point := map[string]json.RawMessage{}
		if err := json.Unmarshal(line, &point); err != nil {
			t.Fatal(err)
		}
		point["seq"] = json.RawMessage(strconv.Itoa(i))
		point["t_mono_ns"] = json.RawMessage(strconv.Itoa(i * 10))
		if err := json.NewEncoder(&buf).Encode(point); err != nil {
			t.Fatal(err)
		}
	}
	c, err := runtimeobs.FromReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeObservation{Source: Input{ID: "synthetic-runtime", Kind: "runtime", Node: c.Node, SHA256: c.SourceSHA}, Capture: c}
}

func TestEmpiricalMeasuredBoundariesRetainCancellationsAndExclusions(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		in := empiricalFixture(t, cancel)
		before, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := FitEmpiricalTimings(in, 1, 4, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Build) != 1 || len(got.Import) != 2 || len(got.Excluded) != 3 {
			t.Fatalf("%+v", got)
		}
		build := got.Build[0]
		if build.BuildID != "runtime-18446744073709551615" || build.Definition != "runtime_worker_entry_to_task_offer" || build.Nanoseconds != 30 || build.FromLine != 10 || build.ToLine != 13 || build.Node != in.Source.Node || build.Input != in.Source.ID || build.Run != in.Capture.Run {
			t.Fatal(build)
		}
		for _, s := range got.Import {
			if s.Nanoseconds != 10 {
				t.Fatal(s)
			}
		}
		if got.Excluded[0].Reason != "not_single_block" || got.Excluded[1].Reason != "not_successful" || got.Excluded[2].Reason != "height_outside_scope" {
			t.Fatal(got.Excluded)
		}
		state := "observed_result"
		if cancel {
			state = "observed_cancellation"
		}
		if got.TaskStates[state] != 1 || got.ImportResults["ok"] != 4 || got.ImportResults["error"] != 1 {
			t.Fatal(got)
		}
		after, err := json.Marshal(in)
		if err != nil || !bytes.Equal(before, after) || in.Capture.RuntimeModelComplete || in.Capture.DeliveryCoverageProven || in.Capture.ApplicationRequestCompletionProven {
			t.Fatal("source promoted or changed", err)
		}
	}
}

func TestEmpiricalTimingsRejectAlteredProjection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*RuntimeObservation)
	}{
		{"source_hash", func(in *RuntimeObservation) { in.Source.SHA256 = strings.Repeat("f", 64) }},
		{"incomplete", func(in *RuntimeObservation) { in.Capture.Complete = false }},
		{"gap", func(in *RuntimeObservation) { in.Capture.SequenceGaps = "1" }},
		{"empty_input", func(in *RuntimeObservation) { in.Source.ID = "" }},
		{"task_clock", func(in *RuntimeObservation) { in.Capture.Tasks[0].Intervals[0].Nanoseconds = "1" }},
		{"task_source", func(in *RuntimeObservation) { in.Capture.Tasks[0].StartLine++ }},
		{"task_stage", func(in *RuntimeObservation) { in.Capture.Tasks[0].Stages[0].Height = "3" }},
		{"duplicate_task", func(in *RuntimeObservation) { in.Capture.Tasks = append(in.Capture.Tasks, in.Capture.Tasks[0]) }},
		{"duplicate_call", func(in *RuntimeObservation) { in.Capture.Calls = append(in.Capture.Calls, in.Capture.Calls[3]) }},
		{"call_clock", func(in *RuntimeObservation) { in.Capture.Calls[3].Nanoseconds = "1" }},
		{"call_height", func(in *RuntimeObservation) { in.Capture.Calls[3].Height = "3" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := empiricalFixture(t, false)
			tc.change(&in)
			if _, err := FitEmpiricalTimings(in, 1, 4, time.Second); err == nil {
				t.Fatal("altered projection accepted")
			}
		})
	}
}

func TestEmpiricalTimingScopeAndBounds(t *testing.T) {
	for _, value := range []string{"", "0", "01", "-1", "+1", "1.0", "18446744073709551616", strings.Repeat("1", 1025)} {
		if empiricalHeightInRange(value, 1, 4) {
			t.Fatal(value)
		}
	}
	if !empiricalHeightInRange("18446744073709551615", ^uint64(0), ^uint64(0)) {
		t.Fatal("full-width height lost")
	}
	in := empiricalFixture(t, false)
	got, err := FitEmpiricalTimings(in, 3, 4, time.Second)
	if err != nil || len(got.Build) != 0 || len(got.Import) != 0 || len(got.Excluded) != 6 {
		t.Fatal(got, err)
	}
	for _, scope := range []struct {
		from, to uint64
		until    time.Duration
	}{{0, 4, time.Second}, {4, 3, time.Second}, {1, 10001, time.Second}, {1, 4, 0}, {1, 4, 25 * time.Hour}} {
		if _, err := FitEmpiricalTimings(in, scope.from, scope.to, scope.until); err == nil {
			t.Fatal(scope)
		}
	}
	got, err = FitEmpiricalTimings(in, 1, 4, 20*time.Nanosecond)
	if err != nil || len(got.Build) != 0 || len(got.Import) != 2 {
		t.Fatal(got, err)
	}
	data, err := json.Marshal(got.Excluded[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fields, map[string]any{"kind": "build", "id": "18446744073709551615", "reason": "interval_unavailable", "from_line": float64(10), "to_line": float64(13)}) {
		t.Fatal(string(data))
	}
}
