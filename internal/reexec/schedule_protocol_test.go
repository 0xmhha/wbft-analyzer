package reexec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

func scheduleReplies(t *testing.T, request map[string]any) []json.RawMessage {
	t.Helper()
	var in, out bytes.Buffer
	enc := json.NewEncoder(&in)
	for _, r := range []map[string]any{{"type": "hello", "protocol": Protocol}, request, {"type": "bye"}} {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := Serve(context.Background(), &in, &out); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&out)
	var replies []json.RawMessage
	for {
		var raw json.RawMessage
		err := dec.Decode(&raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		replies = append(replies, raw)
	}
	return replies
}

func TestLinkedSchedulePreservesSourceAndMarksCounterfactual(t *testing.T) {
	p, chain, _ := simulationInput(t)
	reader, err := journal.OpenReader(nil, p.Input.Path)
	if err != nil {
		t.Fatal(err)
	}
	writer := ""
	var target *journal.StepRec
	for {
		rec, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if seg, ok := rec.Body.(*journal.SegmentRec); ok {
			writer = seg.Run
		}
		if s, ok := rec.Body.(*journal.StepRec); ok && s.InputKind == inputlog.KindCapturedMessage && s.Via == "peer" {
			target = s
			break
		}
	}
	if target == nil {
		t.Fatal("no external recorded input")
	}
	change := stepdriver.TraceSchedule{Action: "drop", WriterRun: writer, EngineRun: target.EngineRun, Step: target.Step}
	request := map[string]any{"type": "replay", "id": 1, "journal": p.Input.Path, "chain": chain, "answer_scope": "context", "input_schedule": change}
	rows := scheduleReplies(t, request)
	var hello reply
	if json.Unmarshal(rows[0], &hello) != nil || !hasIssue(hello.Features, "input_schedule_v1") {
		t.Fatal("schedule capability missing")
	}
	found := false
	empty, err := inputlog.OutDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range rows[1:] {
		var r struct {
			reply
			Scheduled *stepdriver.TraceInputPosition `json:"scheduled_input"`
			Reason    string                         `json:"suppression_reason"`
			Change    *stepdriver.TraceSchedule      `json:"input_schedule"`
		}
		if json.Unmarshal(raw, &r) != nil {
			t.Fatal("invalid reply")
		}
		if r.Type == "error" {
			t.Fatalf("core experiment failed: %s", r.Code)
		}
		if r.Type == "step" {
			if r.Scheduled == nil || r.Scheduled.WriterRun != r.Writer || r.Scheduled.EngineRun != r.Engine || r.Scheduled.Step != r.Step {
				t.Fatal("source coordinates lost")
			}
			if r.Step == target.Step && r.Engine == target.EngineRun && r.Writer == writer {
				found = true
				if !r.Scheduled.Removed || r.Reason != "requested_drop" || r.Digest != digest(empty) || r.Outputs != 0 || !r.Omitted {
					t.Fatal("drop did not execute empty input")
				}
			}
		}
		if r.Type == "done" && (!r.Counterfactual || r.Change == nil || *r.Change != change) {
			t.Fatal("experiment identity lost")
		}
	}
	if !found {
		t.Fatal("target source step absent: " + strconv.FormatUint(target.Step, 10))
	}
	fingerprint, err := messages.Fingerprint(context.Background(), p.Input)
	if err != nil || fingerprint.SHA256 != p.Summary.SHA256 {
		t.Fatal("source bytes changed", err)
	}
	after, err := journal.OpenReader(nil, p.Input.Path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stepdriver.PlanTraceSchedule(after, change); err != nil {
		t.Fatal("untouched source no longer valid", err)
	}
}

func TestLinkedScheduleRefusesConflictingPoliciesBeforeReadingSource(t *testing.T) {
	for _, extra := range []map[string]any{{"answer_scope": "step"}, {"omit_missing_captures": true}, {"warmup_from_height": 1}, {"compare_from_height": 2}} {
		request := map[string]any{"type": "replay", "id": 1, "answer_scope": "context", "input_schedule": stepdriver.TraceSchedule{Action: "drop", WriterRun: "synthetic", EngineRun: 1, Step: 2}}
		for k, v := range extra {
			request[k] = v
		}
		rows := scheduleReplies(t, request)
		var r reply
		if len(rows) != 2 || json.Unmarshal(rows[1], &r) != nil || r.Type != "error" || r.Code != "input_schedule" {
			t.Fatal("conflicting policy accepted")
		}
	}
}
