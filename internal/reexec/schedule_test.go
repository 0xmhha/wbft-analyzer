package reexec

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestInputScheduleRejectsAmbiguousCoordinates(t *testing.T) {
	good := `{"action":"drop","writer_run":"synthetic","engine_run":"18446744073709551615","step":"2"}`
	var s InputSchedule
	if json.Unmarshal([]byte(good), &s) != nil {
		t.Fatal("full uint64 coordinate rejected")
	}
	for _, raw := range []string{strings.Replace(good, `"2"`, `2`, 1), strings.Replace(good, `"2"`, `"02"`, 1), strings.Replace(good, `"2"`, `"0"`, 1), strings.Replace(good, `"drop"`, `"unknown"`, 1), strings.Replace(good, `"step":"2"`, `"step":"2","step":"3"`, 1), strings.Replace(good, `"step":"2"`, `"step":"2","unknown":"x"`, 1)} {
		if json.Unmarshal([]byte(raw), &s) == nil {
			t.Fatal("ambiguous coordinate accepted", raw)
		}
	}
}

type forgedScheduleWriter struct {
	mode string
	out  *os.File
}

func (w forgedScheduleWriter) Write(raw []byte) (int, error) {
	var r map[string]json.RawMessage
	if json.Unmarshal(raw, &r) != nil {
		return 0, ErrHelper
	}
	var kind string
	_ = json.Unmarshal(r["type"], &kind)
	switch {
	case kind == "hello" && w.mode == "old":
		r["features"] = json.RawMessage(`["context_answers_v1"]`)
	case kind == "step" && w.mode == "position":
		if string(r["scheduled_input"]) != "null" {
			var pos map[string]any
			_ = json.Unmarshal(r["scheduled_input"], &pos)
			pos["slot_step"] = float64(999999)
			r["scheduled_input"], _ = json.Marshal(pos)
		}
	case kind == "step" && w.mode == "reservation_prefix":
		var pos map[string]any
		_ = json.Unmarshal(r["scheduled_input"], &pos)
		if pos["execution_step"] == float64(1) {
			r["suppression_reason"] = json.RawMessage(`"reservation_unavailable"`)
			r["omitted"] = json.RawMessage(`true`)
			r["outputs"] = json.RawMessage(`0`)
			r["match"] = json.RawMessage(`false`)
			r["out_digest"], _ = json.Marshal(emptyOutputDigest())
		}
	case kind == "step" && w.mode == "suppression":
		r["suppression_reason"] = json.RawMessage(`"unproven"`)
	case kind == "done" && w.mode == "reservation_prefix":
		var count int64
		_ = json.Unmarshal(r["mismatches"], &count)
		r["mismatches"], _ = json.Marshal(count + 1)
	case kind == "done" && w.mode == "echo":
		r["input_schedule"] = json.RawMessage(`null`)
	}
	result, e := json.Marshal(r)
	if e != nil {
		return 0, e
	}
	_, e = w.out.Write(append(result, '\n'))
	if e != nil {
		return 0, e
	}
	return len(raw), nil
}
func TestScheduleProtocolChild(t *testing.T) {
	if len(os.Args) < 2 {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if !strings.HasPrefix(mode, "schedule-") {
		return
	}
	if Serve(context.Background(), os.Stdin, forgedScheduleWriter{strings.TrimPrefix(mode, "schedule-"), os.Stdout}) != nil {
		os.Exit(2)
	}
	os.Exit(0)
}
func scheduledPlan(t *testing.T) (Plan, *InputSchedule) {
	t.Helper()
	in, chain, genesis := simulationInput(t)
	p, e := Inspect(context.Background(), in, chain, "8282", genesis, 1, 2)
	if e != nil {
		t.Fatal(e)
	}
	r, e := journal.OpenReader(nil, in.Input.Path)
	if e != nil {
		t.Fatal(e)
	}
	writer := ""
	for {
		rec, e := r.Next()
		if e != nil {
			t.Fatal("no external input", e)
		}
		if seg, ok := rec.Body.(*journal.SegmentRec); ok {
			writer = seg.Run
		}
		if s, ok := rec.Body.(*journal.StepRec); ok && s.InputKind == inputlog.KindCapturedMessage && s.Via == "peer" {
			return p, &InputSchedule{Action: "drop", Writer: writer, Engine: strconv.FormatUint(s.EngineRun, 10), Step: strconv.FormatUint(s.Step, 10)}
		}
	}
}
func TestExecuteScheduledCoreAndForgedProtocol(t *testing.T) {
	p, change := scheduledPlan(t)
	h := testHelper(t, "core")
	h.AnswerScope = "context"
	h.Schedule = change
	var rows []Step
	result, e := Execute(context.Background(), p, h, func(s Step) error { rows = append(rows, s); return nil })
	if e != nil || result.Status != "counterfactual" || result.Schedule == nil || len(rows) == 0 {
		t.Fatal(result, e)
	}
	found := false
	for _, s := range rows {
		if s.Scheduled == nil || s.Cursor() != s.Scheduled.SlotOrdinal {
			t.Fatal("execution/source coordinates missing")
		}
		if s.ScheduleReason == "requested_drop" {
			found = true
			if s.Replayed != emptyOutputDigest() {
				t.Fatal("drop output was not empty")
			}
		}
	}
	if !found {
		t.Fatal("target input missing")
	}
	for _, mode := range []string{"old", "position", "suppression", "reservation_prefix", "echo"} {
		t.Run(mode, func(t *testing.T) {
			exe, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			h.Path = exe
			h.Args = []string{"-test.run=^TestScheduleProtocolChild$", "--", "schedule-" + mode}
			h.Timeout = 10 * time.Second
			r, e := Execute(context.Background(), p, h, func(Step) error { return nil })
			if !errors.Is(e, ErrHelper) || r.Status == "reproduced" {
				t.Fatal("forged protocol accepted", r, e)
			}
			if mode == "old" && r.Issue != "input_schedule_unsupported" {
				t.Fatal(r)
			}
		})
	}
	// Slot provenance, rather than the moved source head, bounds borrowed answers.
	if len(p.Answers) > 0 {
		for _, a := range p.Answers {
			s := Step{Ordinal: a.Source.Ordinal, Scheduled: &InputPosition{SlotOrdinal: a.Source.Ordinal}}
			raw := helperAnswerSource{Writer: a.Source.Run, Call: a.Source.Call, Kind: a.Source.Kind, Key: a.Source.Key}
			raw.Engine, _ = strconv.ParseUint(a.Source.Engine, 10, 64)
			raw.Step, _ = strconv.ParseUint(a.Source.Step, 10, 64)
			if _, e := verifiedAnswerSources(p, s, []helperAnswerSource{raw}, map[string]bool{}); e != nil {
				t.Fatal(e)
			}
			s.Scheduled.SlotOrdinal = -1
			if _, e := verifiedAnswerSources(p, s, []helperAnswerSource{raw}, map[string]bool{}); e == nil {
				t.Fatal("unproven execution context accepted")
			}
			break
		}
	}
}
